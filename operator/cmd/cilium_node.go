// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"k8s.io/apimachinery/pkg/api/errors"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"

	"github.com/cilium/cilium/pkg/ipam/allocator"
	cilium_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/informer"
	"github.com/cilium/cilium/pkg/k8s/utils"
	"github.com/cilium/cilium/pkg/kvstore/store"
	nodeStore "github.com/cilium/cilium/pkg/node/store"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/option"
)

// ciliumNodeName is only used to implement NamedKey interface.
type ciliumNodeName struct {
	cluster string
	name    string
}

func (c *ciliumNodeName) GetKeyName() string {
	return nodeTypes.GetKeyNodeName(c.cluster, c.name)
}

type ciliumNodeManagerQueueSyncedKey struct{}

type ciliumNodeSynchronizer struct {
	clientset   k8sClient.Clientset
	nodeManager allocator.NodeEventHandler
	withKVStore bool

	// ciliumNodeStore contains all CiliumNodes present in k8s.
	ciliumNodeStore cache.Store

	k8sCiliumNodesCacheSynced    chan struct{}
	ciliumNodeManagerQueueSynced chan struct{}
}

func newCiliumNodeSynchronizer(clientset k8sClient.Clientset, nodeManager allocator.NodeEventHandler, withKVStore bool) *ciliumNodeSynchronizer {
	return &ciliumNodeSynchronizer{
		clientset:   clientset,
		nodeManager: nodeManager,
		withKVStore: withKVStore,

		k8sCiliumNodesCacheSynced:    make(chan struct{}),
		ciliumNodeManagerQueueSynced: make(chan struct{}),
	}
}

func (s *ciliumNodeSynchronizer) Start(ctx context.Context, wg *sync.WaitGroup) error {
	var (
		ciliumNodeKVStore      *store.SharedStore
		err                    error
		nodeManagerSyncHandler func(key string) error
		kvStoreSyncHandler     func(key string) error
		connectedToKVStore     = make(chan struct{})

		resourceEventHandler   = cache.ResourceEventHandlerFuncs{}
		ciliumNodeManagerQueue = workqueue.NewRateLimitingQueue(workqueue.DefaultControllerRateLimiter())
		kvStoreQueue           = workqueue.NewRateLimitingQueue(workqueue.DefaultControllerRateLimiter())
	)

	// KVStore is enabled -> we will run the event handler to sync objects into
	// KVStore.
	if s.withKVStore {
		// Connect to the KVStore asynchronously so that we are able to start
		// the operator without relying on the KVStore to be up.
		// Start a goroutine to GC all CiliumNodes from the KVStore that are
		// no longer running.
		wg.Add(1)
		go func() {
			defer wg.Done()

			log.Info("Starting to synchronize CiliumNode custom resources to KVStore")

			ciliumNodeKVStore, err = store.JoinSharedStore(store.Configuration{
				Prefix:     nodeStore.NodeStorePrefix,
				KeyCreator: nodeStore.KeyCreator,
			})

			if err != nil {
				log.WithError(err).Fatal("Unable to setup node watcher")
			}
			close(connectedToKVStore)

			<-s.k8sCiliumNodesCacheSynced
			// Since we processed all events received from k8s we know that
			// at this point the list in ciliumNodeStore should be the source of
			// truth and we need to delete all nodes in the kvNodeStore that are
			// *not* present in the ciliumNodeStore.
			listOfCiliumNodes := s.ciliumNodeStore.ListKeys()

			kvStoreNodes := ciliumNodeKVStore.SharedKeysMap()

			for _, ciliumNode := range listOfCiliumNodes {
				// The remaining kvStoreNodes are leftovers that need to be GCed
				kvStoreNodeName := nodeTypes.GetKeyNodeName(option.Config.ClusterName, ciliumNode)
				delete(kvStoreNodes, kvStoreNodeName)
			}

			if len(listOfCiliumNodes) == 0 && len(kvStoreNodes) != 0 {
				log.Warn("Preventing GC of nodes in the KVStore due the nonexistence of any CiliumNodes in kube-apiserver")
				return
			}

			for _, kvStoreNode := range kvStoreNodes {
				// Only delete the nodes that belong to our cluster
				if strings.HasPrefix(kvStoreNode.GetKeyName(), option.Config.ClusterName) {
					ciliumNodeKVStore.DeleteLocalKey(ctx, kvStoreNode)
				}
			}
		}()
	} else {
		log.Info("Starting to synchronize CiliumNode custom resources")
	}

	if s.nodeManager != nil {
		nodeManagerSyncHandler = s.syncHandlerConstructor(
			func(node *cilium_v2.CiliumNode) {
				s.nodeManager.Delete(node)
			},
			func(node *cilium_v2.CiliumNode) {
				// node is deep copied before it is stored in pkg/aws/eni
				s.nodeManager.Upsert(node)
			})
	}

	if s.withKVStore {
		kvStoreSyncHandler = s.syncHandlerConstructor(
			func(node *cilium_v2.CiliumNode) {
				nodeDel := ciliumNodeName{
					cluster: option.Config.ClusterName,
					name:    node.Name,
				}
				ciliumNodeKVStore.DeleteLocalKey(ctx, &nodeDel)
			},
			func(node *cilium_v2.CiliumNode) {
				nodeNew := nodeTypes.ParseCiliumNode(node)
				ciliumNodeKVStore.UpdateKeySync(ctx, &nodeNew, false)
			})
	}

	// If both nodeManager and KVStore are nil, then we don't need to handle
	// any watcher events, but we will need to keep all CiliumNodes in
	// memory because 'ciliumNodeStore' is used across the operator
	// to get the latest state of a CiliumNode.
	if s.withKVStore || s.nodeManager != nil {
		resourceEventHandler = cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				key, err := cache.DeletionHandlingMetaNamespaceKeyFunc(obj)
				if err != nil {
					log.WithError(err).Warning("Unable to process CiliumNode Add event")
					return
				}
				if s.nodeManager != nil {
					ciliumNodeManagerQueue.Add(key)
				}
				if s.withKVStore {
					kvStoreQueue.Add(key)
				}
			},
			UpdateFunc: func(oldObj, newObj interface{}) {
				if oldNode := informer.CastInformerEvent[cilium_v2.CiliumNode](oldObj); oldNode != nil {
					if newNode := informer.CastInformerEvent[cilium_v2.CiliumNode](newObj); newNode != nil {
						if oldNode.DeepEqual(newNode) {
							return
						}
						key, err := cache.DeletionHandlingMetaNamespaceKeyFunc(newObj)
						if err != nil {
							log.WithError(err).Warning("Unable to process CiliumNode Update event")
							return
						}
						if s.nodeManager != nil {
							ciliumNodeManagerQueue.Add(key)
						}
						if s.withKVStore {
							kvStoreQueue.Add(key)
						}
					} else {
						log.Warningf("Unknown CiliumNode object type %T received: %+v", newNode, newNode)
					}
				} else {
					log.Warningf("Unknown CiliumNode object type %T received: %+v", oldNode, oldNode)
				}
			},
			DeleteFunc: func(obj interface{}) {
				key, err := cache.DeletionHandlingMetaNamespaceKeyFunc(obj)
				if err != nil {
					log.WithError(err).Warning("Unable to process CiliumNode Delete event")
					return
				}
				if s.nodeManager != nil {
					ciliumNodeManagerQueue.Add(key)
				}
				if s.withKVStore {
					kvStoreQueue.Add(key)
				}
			},
		}
	}

	// TODO: The operator is currently storing a full copy of the
	// CiliumNode resource, as the resource grows, we may want to consider
	// introducing a slim version of it.
	var ciliumNodeInformer cache.Controller
	s.ciliumNodeStore, ciliumNodeInformer = informer.NewInformer(
		utils.ListerWatcherFromTyped[*cilium_v2.CiliumNodeList](s.clientset.CiliumV2().CiliumNodes()),
		&cilium_v2.CiliumNode{},
		0,
		resourceEventHandler,
		nil,
	)

	wg.Add(1)
	go func() {
		defer wg.Done()

		cache.WaitForCacheSync(ctx.Done(), ciliumNodeInformer.HasSynced)
		close(s.k8sCiliumNodesCacheSynced)
		ciliumNodeManagerQueue.Add(ciliumNodeManagerQueueSyncedKey{})
		log.Info("CiliumNodes caches synced with Kubernetes")
		// Only handle events if nodeManagerSyncHandler is not nil. If it is nil
		// then there isn't any event handler set for CiliumNodes events.
		if nodeManagerSyncHandler != nil {
			go func() {
				// infinite loop. run in a goroutine to unblock code execution
				for s.processNextWorkItem(ciliumNodeManagerQueue, nodeManagerSyncHandler) {
				}
			}()
		}
		// Start handling events for KVStore **after** nodeManagerSyncHandler
		// otherwise Cilium Operator will block until the KVStore is available.
		// This might be problematic in clusters that have etcd-operator with
		// cluster-pool ipam mode because they depend on Cilium Operator to be
		// running and handling IP Addresses with nodeManagerSyncHandler.
		// Only handle events if kvStoreSyncHandler is not nil. If it is nil
		// then there isn't any event handler set for CiliumNodes events.
		if s.withKVStore && kvStoreSyncHandler != nil {
			<-connectedToKVStore
			log.Info("Connected to the KVStore, syncing CiliumNodes to the KVStore")
			// infinite loop it will block code execution
			for s.processNextWorkItem(kvStoreQueue, kvStoreSyncHandler) {
			}
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		defer kvStoreQueue.ShutDown()
		defer ciliumNodeManagerQueue.ShutDown()

		ciliumNodeInformer.Run(ctx.Done())
	}()

	return nil
}

func (s *ciliumNodeSynchronizer) syncHandlerConstructor(notFoundHandler func(node *cilium_v2.CiliumNode), foundHandler func(node *cilium_v2.CiliumNode)) func(key string) error {
	return func(key string) error {
		_, name, err := cache.SplitMetaNamespaceKey(key)
		if err != nil {
			log.WithError(err).Error("Unable to process CiliumNode event")
			return err
		}
		obj, exists, err := s.ciliumNodeStore.GetByKey(name)

		// Delete handling
		if !exists || errors.IsNotFound(err) {
			notFoundHandler(&cilium_v2.CiliumNode{
				ObjectMeta: meta_v1.ObjectMeta{
					Name: name,
				},
			})
			return nil
		}
		if err != nil {
			log.WithError(err).Warning("Unable to retrieve CiliumNode from watcher store")
			return err
		}
		cn, ok := obj.(*cilium_v2.CiliumNode)
		if !ok {
			tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
			if !ok {
				return fmt.Errorf("couldn't get object from tombstone %T", obj)
			}
			cn, ok = tombstone.Obj.(*cilium_v2.CiliumNode)
			if !ok {
				return fmt.Errorf("tombstone contained object that is not a *cilium_v2.CiliumNode %T", obj)
			}
		}
		if cn.DeletionTimestamp != nil {
			notFoundHandler(cn)
			return nil
		}
		foundHandler(cn)
		return nil
	}
}

// processNextWorkItem process all events from the workqueue.
func (s *ciliumNodeSynchronizer) processNextWorkItem(queue workqueue.RateLimitingInterface, syncHandler func(key string) error) bool {
	key, quit := queue.Get()
	if quit {
		return false
	}
	defer queue.Done(key)

	if _, ok := key.(ciliumNodeManagerQueueSyncedKey); ok {
		close(s.ciliumNodeManagerQueueSynced)
		return true
	}

	err := syncHandler(key.(string))
	if err == nil {
		// If err is nil we can forget it from the queue, if it is not nil
		// the queue handler will retry to process this key until it succeeds.
		queue.Forget(key)
		return true
	}

	log.WithError(err).Errorf("sync %q failed with %v", key, err)
	queue.AddRateLimited(key)

	return true
}

type ciliumNodeUpdateImplementation struct {
	clientset k8sClient.Clientset
}

func (c *ciliumNodeUpdateImplementation) Create(node *cilium_v2.CiliumNode) (*cilium_v2.CiliumNode, error) {
	return c.clientset.CiliumV2().CiliumNodes().Create(context.TODO(), node, meta_v1.CreateOptions{})
}

func (c *ciliumNodeUpdateImplementation) Get(node string) (*cilium_v2.CiliumNode, error) {
	return c.clientset.CiliumV2().CiliumNodes().Get(context.TODO(), node, meta_v1.GetOptions{})
}

func (c *ciliumNodeUpdateImplementation) UpdateStatus(origNode, node *cilium_v2.CiliumNode) (*cilium_v2.CiliumNode, error) {
	if origNode == nil || !origNode.Status.DeepEqual(&node.Status) {
		return c.clientset.CiliumV2().CiliumNodes().UpdateStatus(context.TODO(), node, meta_v1.UpdateOptions{})
	}
	return nil, nil
}

func (c *ciliumNodeUpdateImplementation) Update(origNode, node *cilium_v2.CiliumNode) (*cilium_v2.CiliumNode, error) {
	if origNode == nil || !origNode.Spec.DeepEqual(&node.Spec) {
		return c.clientset.CiliumV2().CiliumNodes().Update(context.TODO(), node, meta_v1.UpdateOptions{})
	}
	return nil, nil
}
