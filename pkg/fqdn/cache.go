// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package fqdn

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"maps"
	"net/netip"
	"regexp"
	"slices"
	"sort"
	"unsafe"

	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/option"
	ciliumslices "github.com/cilium/cilium/pkg/slices"
	"github.com/cilium/cilium/pkg/time"
)

// cacheEntry objects hold data passed in via DNSCache.Update, nominally
// equating to a DNS lookup. They are internal to DNSCache and should not be
// returned.
// cacheEntry objects are immutable once created; the address of an instance is
// a unique identifier.
// Note: the JSON names are intended to correlate to field names from
// api/v1/models.DNSLookup to allow dumping the json from
// `cilium fqdn cache list` to a file that can be unmarshalled via
// `--tofqdns-per-cache`
type cacheEntry struct {
	// Name is a DNS name, it my be not fully qualified (e.g. myservice.namespace)
	Name string `json:"fqdn,omitempty"`

	// LookupTime is when the data begins being valid
	LookupTime time.Time `json:"lookup-time,omitempty"`

	// ExpirationTime is a calculated time when the DNS data stops being valid.
	// It is simply LookupTime + TTL
	ExpirationTime time.Time `json:"expiration-time,omitempty"`

	// TTL represents the number of seconds past LookupTime that this data is
	// valid.
	TTL int `json:"ttl,omitempty"`

	// IPs are the IPs associated with Name for this cacheEntry.
	IPs []netip.Addr `json:"ips,omitempty"`
}

// isExpiredBy returns true if entry is no longer valid at pointInTime
func (entry *cacheEntry) isExpiredBy(pointInTime time.Time) bool {
	return pointInTime.After(entry.ExpirationTime)
}

// ipEntries maps a unique IP to the cacheEntry that provides it in .IPs.
// Multiple IPs may point to the same cacheEntry, or they may all be different.
// Crucially, an IP may be present in a cacheEntry but the IP in ipEntries
// points to another cacheEntry. This is because the second cacheEntry has a
// later expiration for this specific IP, and may not include the other IPs
// provided by the first entry.
// The DNS name in the entries is not checked, but is assumed to be the same
// for all entries.
// Note: They are guarded by the DNSCache mutex.
type ipEntries map[netip.Addr]*cacheEntry

// nameEntries maps a DNS name to the cache entry that inserted it into the
// cache. It used in reverse DNS lookups. It is similar to ipEntries, above,
// but the key is a DNS name.
type nameEntries map[string]*cacheEntry

// getIPs returns an unsorted list of non-expired unique IPs.
// This needs a read-lock
func (s ipEntries) getIPs(now time.Time) []netip.Addr {
	ips := make([]netip.Addr, 0, len(s)) // worst case size
	for ip, entry := range s {
		if entry != nil && !entry.isExpiredBy(now) {
			ips = append(ips, ip.Unmap())
		}
	}

	return ips
}

// DNSCache manages DNS data that will expire after a certain TTL. Information
// is tracked per-IP address, retaining the latest-expiring DNS data for each
// address.
// For most real-world DNS data, the entry per name remains small because newer
// lookups replace older ones. Large TTLs may cause entries to grow if many
// unique IPs are returned in separate lookups.
// It is critical to run .GC periodically. This cleans up expired entries and
// steps forward the time used to determine that entries are expired. This
// means that the Lookup functions may return expired entries until GC is
// called.
// Redundant entries are removed on insert.
type DNSCache struct {
	mu lock.RWMutex

	// forward DNS lookups name -> IPEntries
	// IPEntries maps IP -> entry that provides it. An entry may provide multiple IPs.
	forward map[string]ipEntries

	// IP->dnsNames lookup
	// This map is subordinate to forward, above. An IP inserted into forward, or
	// expired in forward, should also be added/removed in reverse.
	reverse map[netip.Addr]nameEntries

	// LastCleanup is the latest time for which entries have been expired. It is
	// used as "now" when doing lookups and advanced by calls to .GC
	// When an entry is added with an expiration time before lastCleanup, it is
	// set to that value.
	lastCleanup time.Time

	// cleanup maps the TTL expiration times (in seconds since the epoch) to
	// DNS names that expire in that second. On every new insertion where the
	// new data is actually inserted into the cache (i.e. it expires later than
	// an existing entry) cleanup will be updated. CleanupExpiredEntries cleans
	// up these entries on demand.
	// Note: Lookup functions will not return expired entries, and this is used
	// to proactively enforce expirations.
	// Note: It is important to periodically call CleanupExpiredEntries
	// otherwise this map will grow forever.
	cleanup map[int64][]string

	// overLimit is a set of DNS names that were over the per-host configured
	// limit when they received an update. The excess IPs will be removed when
	// cleanupOverLimitEntries is called, but will continue to be returned by
	// Lookup until then.
	// Note: It is important to periodically call GC otherwise this map will
	// grow forever (it is very bounded, however).
	overLimit map[string]bool

	// perHostLimit is the number of maximum number of IP per host.
	perHostLimit int

	// minTTL is the minimum TTL value that a cache entry can have, if the TTL
	// sent in the Update is lower, the TTL will be overwritten to this value.
	// Due is only read-only is not protected by the mutex.
	minTTL int
}

// NewDNSCache returns an initialized DNSCache
func NewDNSCache(minTTL int) *DNSCache {
	c := &DNSCache{
		forward: make(map[string]ipEntries),
		reverse: make(map[netip.Addr]nameEntries),
		// lastCleanup is populated on the first insert
		cleanup:      map[int64][]string{},
		overLimit:    map[string]bool{},
		perHostLimit: 0,
		minTTL:       minTTL,
	}
	return c
}

// NewDNSCache returns an initialized DNSCache and set the max host limit to
// the given argument
func NewDNSCacheWithLimit(minTTL int, limit int) *DNSCache {
	c := NewDNSCache(minTTL)
	c.perHostLimit = limit
	return c
}

func (c *DNSCache) DisableCleanupTrack() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cleanup = nil
}

// Update inserts a new entry into the cache.
// After insertion cache entries for name are expired and redundant entries
// evicted. This is O(number of new IPs) for eviction, and O(number of IPs for
// name) for expiration.
// lookupTime is the time the DNS information began being valid. It should be
// in the past.
// name is used as is and may be an unqualified name (e.g. myservice.namespace).
// ips may be an IPv4 or IPv6 IP. Duplicates will be removed.
// ttl is the DNS TTL for ips and is a seconds value.
func (c *DNSCache) Update(lookupTime time.Time, name string, ips []netip.Addr, ttl int) bool {
	if c.minTTL > ttl {
		ttl = c.minTTL
	}

	entry := &cacheEntry{
		Name:           name,
		LookupTime:     lookupTime,
		ExpirationTime: lookupTime.Add(time.Duration(ttl) * time.Second),
		TTL:            ttl,
		IPs:            ips,
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	return c.updateWithEntry(entry)
}

// updateWithEntry implements the insertion of a cacheEntry. It is used by
// DNSCache.Update and DNSCache.UpdateWithEntry.
// This needs a write lock
func (c *DNSCache) updateWithEntry(entry *cacheEntry) bool {
	changed := false
	entries, exists := c.forward[entry.Name]
	if !exists {
		changed = true
		entries = make(map[netip.Addr]*cacheEntry)
		c.forward[entry.Name] = entries
	}

	if c.updateWithEntryIPs(entries, entry) {
		changed = true
	}

	if c.perHostLimit > 0 && len(entries) > c.perHostLimit {
		c.overLimit[entry.Name] = true
	}
	return changed
}

// AddNameToCleanup adds the IP with the given TTL to the cleanup map to
// delete the entry from the policy when it expires.
// Need to be called with a write lock
func (c *DNSCache) addNameToCleanup(entry *cacheEntry) {
	if c.cleanup == nil {
		return
	}
	if c.lastCleanup.IsZero() || entry.ExpirationTime.Before(c.lastCleanup) {
		c.lastCleanup = entry.ExpirationTime
	}
	expiration := entry.ExpirationTime.Unix()
	expiredEntries, exists := c.cleanup[expiration]
	if !exists {
		expiredEntries = []string{}
	}
	c.cleanup[expiration] = append(expiredEntries, entry.Name)
}

// cleanupExpiredEntries cleans all the expired entries since lastCleanup up to
// expires, but not including it. lastCleanup is set to expires and later
// cleanups begin from that time.
// It returns the list of names that have expired data and a map of removed DNS
// cache entries, keyed by IP.
func (c *DNSCache) cleanupExpiredEntries(expires time.Time) (affectedNames sets.Set[string], removed map[netip.Addr][]*cacheEntry) {
	if c.lastCleanup.IsZero() {
		return nil, nil
	}

	toCleanNames := sets.New[string]()
	for c.lastCleanup.Before(expires) {
		key := c.lastCleanup.Unix()
		if entries, exists := c.cleanup[key]; exists {
			toCleanNames.Insert(entries...)
			delete(c.cleanup, key)
		}
		c.lastCleanup = c.lastCleanup.Add(time.Second).Truncate(time.Second)
	}

	affectedNames = sets.New[string]()
	removed = make(map[netip.Addr][]*cacheEntry)
	for name := range toCleanNames {
		if entries, exists := c.forward[name]; exists {
			affectedNames.Insert(name)
			for ip, entry := range c.removeExpired(entries, c.lastCleanup, time.Time{}) {
				removed[ip] = append(removed[ip], entry)
			}
		}
	}

	return affectedNames, removed
}

// cleanupOverLimitEntries returns the names that has reached the max number of
// IP per host. Internally the function sort the entries by the expiration
// time.
func (c *DNSCache) cleanupOverLimitEntries() (affectedNames sets.Set[string], removed map[netip.Addr][]*cacheEntry) {
	type IPEntry struct {
		ip    netip.Addr
		entry *cacheEntry
	}

	// For global cache the limit maybe is not used at all.
	if c.perHostLimit == 0 {
		return nil, nil
	}

	affectedNames = sets.New[string]()
	removed = make(map[netip.Addr][]*cacheEntry)

	for dnsName := range c.overLimit {
		entries, ok := c.forward[dnsName]
		if !ok {
			continue
		}
		overlimit := len(entries) - c.perHostLimit
		if overlimit <= 0 {
			continue
		}
		sortedEntries := make([]IPEntry, 0, len(entries))
		for ip, entry := range entries {
			sortedEntries = append(sortedEntries, IPEntry{ip, entry})
		}

		sort.Slice(sortedEntries, func(i, j int) bool {
			return sortedEntries[i].entry.ExpirationTime.Before(sortedEntries[j].entry.ExpirationTime)
		})

		for i := range overlimit {
			key := sortedEntries[i]
			delete(entries, key.ip)
			c.remove(key.ip, key.entry)
			removed[key.ip] = append(removed[key.ip], key.entry)
		}
		affectedNames.Insert(dnsName)
	}
	c.overLimit = map[string]bool{}
	return affectedNames, removed
}

// GC cleans TTL expired entries up to now, and overlimit entries, returning
// both sets.
// If zombies is passed in, expired IPs are inserted into it. GC and
// other management of zombies is left to the caller.
// Note: zombies use the original lookup's ExpirationTime for DeletePendingAt,
// not the now parameter. This allows better ordering in zombie GC.
func (c *DNSCache) GC(now time.Time, zombies *DNSZombieMappings) (affectedNames sets.Set[string]) {
	c.mu.Lock()
	expiredNames, expiredEntries := c.cleanupExpiredEntries(now)
	overLimitNames, overLimitEntries := c.cleanupOverLimitEntries()
	c.mu.Unlock()

	if zombies != nil {
		// Iterate over 2 maps
		for _, m := range []map[netip.Addr][]*cacheEntry{
			expiredEntries,
			overLimitEntries,
		} {
			for ip, entries := range m {
				for _, entry := range entries {
					// Set the expiration time to either the GC or the expiration time
					// of the DNS lookup if it is in the future.
					// This can be the case when entries are not expired, but they are
					// over limit. We preserve this time so that, in the event that
					// non-expired names are GC'd, they will be less preferentially reaped
					// by zombies.
					expireTime := now
					if entry.ExpirationTime.After(expireTime) {
						expireTime = entry.ExpirationTime
					}
					zombies.Upsert(expireTime, ip, entry.Name)
				}
			}
		}
	}

	return expiredNames.Union(overLimitNames)
}

// UpdateFromCache is a utility function that allows updating a DNSCache
// instance with all the internal entries of another. Latest-Expiration still
// applies, thus the merged outcome is consistent with adding the entries
// individually.
// When namesToUpdate has non-zero length only those names are updated from
// update, otherwise all DNS names in update are used.
func (c *DNSCache) UpdateFromCache(update *DNSCache, namesToUpdate []string) {
	if update == nil {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	c.updateFromCache(update, namesToUpdate)
}

func (c *DNSCache) updateFromCache(update *DNSCache, namesToUpdate []string) {
	update.mu.RLock()
	defer update.mu.RUnlock()

	if len(namesToUpdate) == 0 {
		for name := range update.forward {
			namesToUpdate = append(namesToUpdate, name)
		}
	}
	for _, name := range namesToUpdate {
		newEntries, exists := update.forward[name]
		if !exists {
			continue
		}
		for _, newEntry := range newEntries {
			c.updateWithEntry(newEntry)
		}
	}
}

// ReplaceFromCacheByNames operates as an atomic combination of ForceExpire and
// multiple UpdateFromCache invocations. The result is to collect all entries
// for DNS names in namesToUpdate from each DNSCache in updates, replacing the
// current entries for each of those names.
func (c *DNSCache) ReplaceFromCacheByNames(namesToUpdate []string, updates ...*DNSCache) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Remove any DNS name in namesToUpdate with a lookup before "now". This
	// effectively deletes all lookups because we're holding the lock.
	c.forceExpireByNames(time.Now(), namesToUpdate)

	for _, update := range updates {
		c.updateFromCache(update, namesToUpdate)
	}
}

// Lookup returns a set of unique IPs that are currently unexpired for name, if
// any exist. An empty list indicates no valid records exist. The IPs are
// returned unsorted.
func (c *DNSCache) Lookup(name string) (ips []netip.Addr) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return c.lookupByTime(c.lastCleanup, name)
}

// lookupByTime takes a timestamp for expiration comparisons, and is only
// intended for testing.
func (c *DNSCache) lookupByTime(now time.Time, name string) (ips []netip.Addr) {
	entries, found := c.forward[name]
	if !found {
		return nil
	}

	return entries.getIPs(now)
}

// LookupByRegexp returns all non-expired cache entries that match re as a map
// of name -> IPs
func (c *DNSCache) LookupByRegexp(re *regexp.Regexp) (matches map[string][]netip.Addr) {
	return c.lookupByRegexpByTime(c.lastCleanup, re)
}

// lookupByRegexpByTime takes a timestamp for expiration comparisons, and is
// only intended for testing.
func (c *DNSCache) lookupByRegexpByTime(now time.Time, re *regexp.Regexp) (matches map[string][]netip.Addr) {
	matches = make(map[string][]netip.Addr)

	c.mu.RLock()
	defer c.mu.RUnlock()

	for name, entry := range c.forward {
		if re.MatchString(name) {
			if ips := entry.getIPs(now); len(ips) > 0 {
				matches[name] = ips
			}
		}
	}

	return matches
}

// LookupIP returns all DNS names in entries that include that IP. The cache
// maintains the latest-expiring entry per-name per-IP. This means that multiple
// names referring to the same IP will expire from the cache at different times,
// and only 1 entry for each name-IP pair is internally retained.
func (c *DNSCache) LookupIP(ip netip.Addr) (names []string) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return c.lookupIPByTime(c.lastCleanup, ip)
}

// lookupIPByTime takes a timestamp for expiration comparisons, and is
// only intended for testing.
func (c *DNSCache) lookupIPByTime(now time.Time, ip netip.Addr) (names []string) {
	cacheEntries, found := c.reverse[ip]
	if !found {
		return nil
	}

	for name, entry := range cacheEntries {
		if entry != nil && !entry.isExpiredBy(now) {
			names = append(names, name)
		}
	}

	slices.Sort(names)
	return names
}

// RemoveKnown removes all ip-name associations from mappings which are known to
// the cache.
func (c *DNSCache) RemoveKnown(mappings map[netip.Addr][]string) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	for ip, names := range mappings {
		rnames, exists := c.reverse[ip]
		if !exists || len(rnames) == 0 {
			continue
		}

		mappings[ip] = slices.DeleteFunc(names, func(name string) bool {
			_, ok := rnames[name]
			return ok
		})
	}
}

// updateWithEntryIPs adds a mapping for every IP found in `entry` to `ipEntries`
// (which maps IP -> cacheEntry). It will replace existing IP->old mappings in
// `entries` if the current entry expires sooner (or has already expired).
// This needs a write lock
func (c *DNSCache) updateWithEntryIPs(entries ipEntries, entry *cacheEntry) bool {
	added := false
	for _, ip := range entry.IPs {
		old, exists := entries[ip]
		if old == nil || !exists || old.isExpiredBy(entry.ExpirationTime) {
			entries[ip] = entry
			c.upsertReverse(ip, entry)
			c.addNameToCleanup(entry)
			added = true
		}
	}
	return added

}

// removeExpired removes expired (or nil) cacheEntry pointers from entries, an
// ipEntries instance for a specific name. It returns a boolean if any entry is
// removed.
// now is the "current time" and entries with ExpirationTime before then are
// removed.
// expireLookupsBefore is an optional parameter. It causes any entry with a
// LookupTime before it to be expired. It is intended for use with cache
// clearing functions like ForceExpire, and does not maintain the cache's
// guarantees.
// This needs a write lock
func (c *DNSCache) removeExpired(entries ipEntries, now time.Time, expireLookupsBefore time.Time) (removed ipEntries) {
	removed = make(ipEntries)
	for ip, entry := range entries {
		if entry == nil || entry.isExpiredBy(now) || entry.LookupTime.Before(expireLookupsBefore) {
			delete(entries, ip)
			c.remove(ip, entry)
			removed[ip] = entry
		}
	}

	return removed
}

// upsertReverse updates the reverse DNS cache for ip with entry, if it expires
// later than the already-stored entry.
// It is assumed that entry includes ip.
// This needs a write lock
func (c *DNSCache) upsertReverse(ip netip.Addr, entry *cacheEntry) {
	entries, exists := c.reverse[ip]
	if entries == nil || !exists {
		entries = make(map[string]*cacheEntry)
		c.reverse[ip] = entries
	}
	entries[entry.Name] = entry
}

// remove removes the reference between ip and the name stored in entry from
// the DNS cache (both in forward and reverse maps). This assumes the write
// lock is taken.
func (c *DNSCache) remove(ip netip.Addr, entry *cacheEntry) {
	c.removeForward(ip, entry)
	c.removeReverse(ip, entry)
}

// removeForward removes the reference between ip and the name stored in entry.
// When no more references from ip to any name exist, the map entry is deleted
// outright.
// It is assumed that entry includes ip.
// This needs a write lock.
func (c *DNSCache) removeForward(ip netip.Addr, entry *cacheEntry) {
	entries, exists := c.forward[entry.Name]
	if entries == nil || !exists {
		return
	}
	delete(entries, ip)
	if len(entries) == 0 {
		delete(c.forward, entry.Name)
	}
}

// removeReverse is the equivalent of removeForward() but for the reverse map.
func (c *DNSCache) removeReverse(ip netip.Addr, entry *cacheEntry) {
	entries, exists := c.reverse[ip]
	if entries == nil || !exists {
		return
	}
	delete(entries, entry.Name)
	if len(entries) == 0 {
		delete(c.reverse, ip)
	}
}

// GetIPs takes a snapshot of all IPs in the reverse cache.
func (c *DNSCache) GetIPs() map[netip.Addr][]string {
	c.mu.RLock()
	defer c.mu.RUnlock()

	out := make(map[netip.Addr][]string, len(c.reverse))

	for ip, names := range c.reverse {
		out[ip] = slices.Collect(maps.Keys(names))
	}

	return out
}

// ForceExpire is used to clear entries from the cache before their TTL is
// over. This operation does not keep previous guarantees that, for each IP,
// the most recent lookup to provide that IP is used.
// Note that all parameters must match, if provided. `time.Time{}` is the
// match-all time parameter.
// For example:
//
//	ForceExpire(time.Time{}, 'cilium.io') expires all entries for cilium.io.
//	ForceExpire(time.Now(), 'cilium.io') expires all entries for cilium.io
//	that expired or had a lookup time before the current time.
//
// expireLookupsBefore requires a lookup to have a LookupTime before it in
// order to remove it.
// nameMatch will remove any DNS names that match.
func (c *DNSCache) ForceExpire(expireLookupsBefore time.Time, nameMatch *regexp.Regexp) (namesAffected sets.Set[string]) {
	c.mu.Lock()
	defer c.mu.Unlock()

	namesAffected = sets.New[string]()

	for name, entries := range c.forward {
		// If nameMatch was passed in, we must match it. Otherwise, "match all".
		if nameMatch != nil && !nameMatch.MatchString(name) {
			continue
		}
		// We pass expireLookupsBefore as the `now` parameter but it is redundant
		// because LookupTime must be before ExpirationTime.
		// The second expireLookupsBefore actually matches lookup times, and will
		// delete the entries completely.
		for _, entry := range c.removeExpired(entries, expireLookupsBefore, expireLookupsBefore) {
			namesAffected.Insert(entry.Name)
		}
	}

	return namesAffected
}

func (c *DNSCache) forceExpireByNames(expireLookupsBefore time.Time, names []string) {
	for _, name := range names {
		entries, exists := c.forward[name]
		if !exists {
			continue
		}

		// We pass expireLookupsBefore as the `now` parameter but it is redundant
		// because LookupTime must be before ExpirationTime.
		// The second expireLookupsBefore actually matches lookup times, and will
		// delete the entries completely.
		c.removeExpired(entries, expireLookupsBefore, expireLookupsBefore)
	}
}

// Dump returns unexpired cache entries in the cache. They are deduplicated,
// but not usefully sorted. These objects should not be modified.
func (c *DNSCache) Dump() (lookups []*cacheEntry) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	// Collect all the still-valid entries
	lookups = make([]*cacheEntry, 0, len(c.forward))
	for _, entries := range c.forward {
		for _, entry := range entries {
			lookups = append(lookups, entry)
		}
	}

	// Dedup the entries. They are created once and are immutable so the address
	// is a unique identifier.
	// We iterate through the list, keeping unique pointers. This is correct
	// because the list is sorted and, if two consecutive entries are the same,
	// it is safe to overwrite the second duplicate.
	sort.Slice(lookups, func(i, j int) bool {
		return uintptr(unsafe.Pointer(lookups[i])) < uintptr(unsafe.Pointer(lookups[j]))
	})

	deduped := lookups[:0] // len==0 but cap==cap(lookups)
	for readIdx, lookup := range lookups {
		if readIdx == 0 || deduped[len(deduped)-1] != lookups[readIdx] {
			deduped = append(deduped, lookup)
		}
	}

	return deduped
}

// Count returns two values, the count of still-valid FQDNs inside the DNS
// cache and the count of the still-valid entries (IPs) in the DNS cache.
//
// The FQDN count returns the length of the DNS cache size.
//
// The IP count is not deduplicated, see Dump(). In other words, this value
// represents an accurate tally of IPs associated with an FQDN in the DNS
// cache.
func (c *DNSCache) Count() (uint64, uint64) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	var ips uint64
	for _, entries := range c.forward {
		ips += uint64(len(entries))
	}
	return uint64(len(c.forward)), ips
}

// MarshalJSON serialises the set of DNS lookup cacheEntries needed to
// reconstruct this cache instance.
// Note: Expiration times are honored and the reconstructed cache instance is
// expected to return the same values as the original at that point in time.
func (c *DNSCache) MarshalJSON() ([]byte, error) {
	lookups := c.Dump()

	// serialise into a JSON object array
	return json.Marshal(lookups)
}

// UnmarshalJSON rebuilds a DNSCache from serialized JSON.
// Note: This is destructive to any correct data. Use UpdateFromCache for bulk
// updates.
func (c *DNSCache) UnmarshalJSON(raw []byte) error {
	lookups := make([]*cacheEntry, 0)
	if err := json.Unmarshal(raw, &lookups); err != nil {
		return err
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	c.forward = make(map[string]ipEntries)
	c.reverse = make(map[netip.Addr]nameEntries)

	for _, newLookup := range lookups {
		c.updateWithEntry(newLookup)
	}

	return nil
}

// DNSZombieMapping is an IP that has expired or been evicted from a DNS cache.
// It records the DNS name and IP, along with other bookkeeping timestamps that
// help determine when it can be finally deleted. Zombies are dead when
// they are not marked alive by CT GC.
// Special handling exists when the count of zombies is large. Overlimit
// zombies are deleted in GC with the following preferences (this is cumulative
// and in order of precedence):
//   - Zombies with an earlier AliveAt are evicted before those with a later value
//     (i.e. connections no longer marked as alive by CT GC are evicted first).
//   - Zombies with an earlier DeletePendingAtTime are evicted first.
//     Note: Upsert sets DeletePendingAt on every update, thus making GC prefer
//     to evict IPs with less DNS churn on them.
//   - Zombies with the lowest count of DNS names in them are evicted first
type DNSZombieMapping struct {
	// Names is the list of names that had DNS lookups with this IP. These may
	// derive from unrelated DNS lookups. The list is maintained de-duplicated.
	Names []string `json:"names,omitempty"`

	// IP is an address that is pending for delete but may be in-use by a
	// connection.
	IP netip.Addr `json:"ip,omitempty"`

	// AliveAt is the last time this IP was marked alive via
	// DNSZombieMappings.MarkAlive. At zombie creation time we assume a zombie
	// to be alive and initialize the field to the `lastCTGCUpdate` time. This
	// avoids comparing a zero-valued time.Time as "earlier" than any other
	// AliveAt values.
	//
	// When AliveAt is later than DNSZombieMappings.lastCTGCUpdate the zombie is
	// considered alive.
	AliveAt time.Time `json:"alive-at,omitempty"`

	// DeletePendingAt is the time at which this IP was most-recently scheduled
	// for deletion. This can be updated if an IP expires from the DNS caches
	// multiple times.
	// When DNSZombieMappings.lastCTGCUpdate is earlier than DeletePendingAt a
	// zombie is alive.
	DeletePendingAt time.Time `json:"delete-pending-at,omitempty"`

	// revisionAddedAt is the GCRevision at which this entry was added.
	// garbage collection must run 2 times before the zombie is eligible for deletion
	revisionAddedAt uint64 `json:"-"`
}

// DeepCopy returns a copy of zombie that does not share any internal pointers
// or fields
func (zombie *DNSZombieMapping) DeepCopy() *DNSZombieMapping {
	return &DNSZombieMapping{
		Names:           slices.Clone(zombie.Names),
		IP:              zombie.IP,
		DeletePendingAt: zombie.DeletePendingAt,
		AliveAt:         zombie.AliveAt,
	}
}

// DNSZombieMappings collects DNS Name->IP mappings that may be inactive and
// evicted, and so may be deleted. They are periodically marked alive by the CT
// GC goroutine. When .GC is called, alive and dead zombies are returned,
// allowing us to skip deleting an IP from the global DNS cache to avoid
// breaking connections that outlast the DNS TTL.
type DNSZombieMappings struct {
	logger *slog.Logger
	lock.Mutex
	deletes        map[netip.Addr]*DNSZombieMapping
	lastCTGCUpdate time.Time
	nextCTGCUpdate time.Time // estimated
	// ctGCRevision is a serial number tracking the number of conntrack
	// garbage collection runs. It is used to ensure that entries
	// are not reaped until CT GC has run at least twice.
	ctGCRevision uint64
	max          int // max allowed zombies

	// perHostLimit is the number of maximum number of IP per host.
	perHostLimit int
}

// NewDNSZombieMappings constructs a DNSZombieMappings that is read to use
func NewDNSZombieMappings(logger *slog.Logger, max, perHostLimit int) *DNSZombieMappings {
	return &DNSZombieMappings{
		logger:       logger,
		deletes:      make(map[netip.Addr]*DNSZombieMapping),
		max:          max,
		perHostLimit: perHostLimit,
	}
}

// Upsert enqueues the ip -> qname as a possible deletion. updatedExisting is
// true when an earlier enqueue existed and was updated. If an entry already
// exists and the expiry time is later, it is updated. The same also applies for
// the AliveAt time.
func (zombies *DNSZombieMappings) Upsert(expiryTime time.Time, addr netip.Addr, qname ...string) (updatedExisting bool) {
	zombies.Lock()
	defer zombies.Unlock()

	zombie, updatedExisting := zombies.deletes[addr]
	if !updatedExisting {
		zombie = &DNSZombieMapping{
			Names:           ciliumslices.Unique(qname),
			IP:              addr,
			AliveAt:         zombies.lastCTGCUpdate,
			DeletePendingAt: expiryTime,
			revisionAddedAt: zombies.ctGCRevision,
		}
		zombies.deletes[addr] = zombie
	} else {
		zombie.Names = ciliumslices.Unique(append(zombie.Names, qname...))
		// Keep the latest expiry time
		if expiryTime.After(zombie.DeletePendingAt) {
			zombie.DeletePendingAt = expiryTime
		}
		// and bump the aliveAt.
		if zombies.lastCTGCUpdate.After(zombie.AliveAt) {
			zombie.AliveAt = zombies.lastCTGCUpdate
		}
	}
	return updatedExisting
}

// isConnectionAlive returns true if 'zombie' is considered alive.
// Zombie is considered dead if all of these conditions apply:
// 1. CT GC has run after the DNS Expiry time and grace period (lastCTGCUpdate > DeletePendingAt + GracePeriod), and
// 2. The CT GC run did not mark the Zombie alive (lastCTGCUpdate > AliveAt)
// 3. CT GC has run at least 2 times since Zombie was entered
// otherwise the Zombie is alive.
//
// We wait for 2 complete GC runs, because this entry may have been added in the middle of a GC run,
// in which case it may not have been marked alive. We need to wait for GC to finish at least 2 times
// before we can safely consider it dead.
func (zombies *DNSZombieMappings) isConnectionAlive(zombie *DNSZombieMapping) bool {
	if !zombies.lastCTGCUpdate.After(zombie.DeletePendingAt.Add(option.Config.ToFQDNsIdleConnectionGracePeriod)) {
		return true
	}
	if !zombies.lastCTGCUpdate.After(zombie.AliveAt) {
		return true
	}
	if zombies.ctGCRevision < (zombie.revisionAddedAt + 2) {
		return true
	}
	return false

}

// getAliveNames returns all the names that are alive.
// A name is alive if at least one of the IPs that resolve to it is alive.
// The value of the map contains all IPs for the name (both alive and dead).
func (zombies *DNSZombieMappings) getAliveNames() map[string][]*DNSZombieMapping {
	aliveNames := make(map[string][]*DNSZombieMapping)

	for _, z := range zombies.deletes {
		if zombies.isConnectionAlive(z) {
			for _, name := range z.Names {
				if _, ok := aliveNames[name]; !ok {
					aliveNames[name] = make([]*DNSZombieMapping, 0, 5)
				}
				aliveNames[name] = append(aliveNames[name], z)
			}
		}
	}

	// Add all of the "dead" IPs for live names into the result
	for _, z := range zombies.deletes {
		if !zombies.isConnectionAlive(z) {
			for _, name := range z.Names {
				if _, ok := aliveNames[name]; ok {
					aliveNames[name] = append(aliveNames[name], z)
				}
			}
		}
	}

	return aliveNames
}

// isZombieAlive returns true if zombie is alive
//
// A zombie is alive if its connection is alive or if one of its names is
// alive. The function takes an argument that contains the aliveNames (can be
// obtained via getAliveNames())
func (zombies *DNSZombieMappings) isZombieAlive(zombie *DNSZombieMapping, aliveNames map[string][]*DNSZombieMapping) (alive, overLimit bool) {
	if zombies.isConnectionAlive(zombie) {
		alive = true
		if zombies.perHostLimit == 0 {
			return alive, overLimit
		}
	}

	for _, name := range zombie.Names {
		if z, ok := aliveNames[name]; ok {
			alive = true
			if zombies.perHostLimit == 0 {
				return alive, overLimit
			} else if len(z) > zombies.perHostLimit {
				overLimit = true
				return alive, overLimit
			}
		}
	}

	return alive, overLimit
}

// sortZombieMappingSlice sorts the provided slice so that less important
// zombies shuffle to the front of the slice (from where they are eliminated).
// To achieve this, it sorts by three criteria, in order of priority:
//
// 1. when the connection was last marked alive (earlier == less important)
// 2. when this ip was last scheduled for deletion (earlier == less important)
// 3. tie-break by number of DNS names for that IP
func sortZombieMappingSlice(alive []*DNSZombieMapping) {
	sort.Slice(alive, func(i, j int) bool {
		switch {
		case alive[i].AliveAt.Before(alive[j].AliveAt):
			return true
		case alive[i].AliveAt.After(alive[j].AliveAt):
			return false
		// We have AliveAt equality after this point.
		case alive[i].DeletePendingAt.Before(alive[j].DeletePendingAt):
			return true
		case alive[i].DeletePendingAt.After(alive[j].DeletePendingAt):
			return false
		// DeletePendingAt is also equal. Tie-break by number of Names.
		default:
			return len(alive[i].Names) < len(alive[j].Names)
		}
	})
}

// GC returns alive and dead DNSZombieMapping entries. This removes dead
// zombies internally, and repeated calls will return different data.
// Zombies are alive if they have been marked alive (with MarkAlive). When
// SetCTGCTime is called and an zombie not marked alive, it becomes dead.
// Calling Upsert on a dead zombie will make it alive again.
// Alive zombies are limited by zombies.max. 0 means no zombies are allowed,
// disabling the behavior. It is expected to be a large value and is in place
// to avoid runaway zombie growth when CT GC is at a large interval.
func (zombies *DNSZombieMappings) GC() (alive, dead []*DNSZombieMapping) {
	zombies.Lock()
	defer zombies.Unlock()

	aliveNames := zombies.getAliveNames()

	// Collect zombies we can delete
	for _, zombie := range zombies.deletes {
		zombieAlive, overLimit := zombies.isZombieAlive(zombie, aliveNames)
		if overLimit {
			// No-op: This zombie is part of a name in 'aliveNames'
			// that needs to impose a per-host IP limit. Decide
			// whether to add to alive or dead in the next loop.
		} else if zombieAlive {
			alive = append(alive, zombie.DeepCopy())
		} else {
			// Emit the actual object here since we will no longer update it
			dead = append(dead, zombie)
		}
	}

	if zombies.perHostLimit > 0 {
		warnActiveDNSEntries := false
		deadIdx := len(dead)

		// Find names which have too many IPs associated mark them dead.
		//
		// Multiple names can refer to the same IP, so if we expire the
		// zombie by IP then we need to ensure that it doesn't get
		// added to both 'alive' and 'dead'.
		//
		// 1) Assemble all of the 'dead', starting from 'deadIdx'.
		//    Assemble alive candidates in 'possibleAlive'.
		// 2) Ensure that 'possibleAlive' doesn't contain any of the
		//    entries in 'dead[deadIdx:]'.
		// 3) Add the remaining 'possibleAlive' to 'alive'.
		possibleAlive := make(map[*DNSZombieMapping]struct{})
		for _, aliveIPsForName := range aliveNames {
			if len(aliveIPsForName) <= zombies.perHostLimit {
				// Already handled in the loop above.
				continue
			}
			overLimit := len(aliveIPsForName) - zombies.perHostLimit
			sortZombieMappingSlice(aliveIPsForName)
			dead = append(dead, aliveIPsForName[:overLimit]...)
			for _, z := range aliveIPsForName[overLimit:] {
				possibleAlive[z] = struct{}{}
			}
			if dead[len(dead)-1].AliveAt.After(zombies.lastCTGCUpdate) {
				warnActiveDNSEntries = true
			}
		}
		if warnActiveDNSEntries {
			zombies.logger.Warn(fmt.Sprintf("Evicting expired DNS cache entries that may be in-use due to per-host limits. This may cause recently created connections to be disconnected. Raise %s to mitigate this.", option.ToFQDNsMaxIPsPerHost))
		}

		for _, dead := range dead[deadIdx:] {
			delete(possibleAlive, dead)
		}

		for zombie := range possibleAlive {
			alive = append(alive, zombie.DeepCopy())
		}
	}

	// Limit alive zombies to max. This is messy, and will break some existing
	// connections. We sort by whether the connection is marked alive or not, the
	// oldest created connections, and tie-break by the number of DNS names for
	// that IP.
	overLimit := len(alive) - zombies.max
	if overLimit > 0 {
		sortZombieMappingSlice(alive)
		dead = append(dead, alive[:overLimit]...)
		alive = alive[overLimit:]
		if dead[len(dead)-1].AliveAt.After(zombies.lastCTGCUpdate) {
			zombies.logger.Warn("Evicting expired DNS cache entries that may be in-use. This may cause recently created connections to be disconnected. Raise --tofqdns-max-deferred-connection-deletes to mitigate this.")
		}
	}

	// Delete the zombies we collected above from the internal map
	for _, zombie := range dead {
		delete(zombies.deletes, zombie.IP)
	}

	return alive, dead
}

// MarkAlive makes an zombie alive and not dead. When now is later than the
// time set with SetCTGCTime the zombie remains alive.
func (zombies *DNSZombieMappings) MarkAlive(now time.Time, ip netip.Addr) {
	zombies.Lock()
	defer zombies.Unlock()

	if zombie, exists := zombies.deletes[ip]; exists {
		zombie.AliveAt = now
	}
}

// SetCTGCTime marks the start of the most recent CT GC. This must be set after
// all MarkAlive calls complete to avoid a race between the DNS garbage
// collector and the CT GC. This would occur when a DNS zombie that has not
// been visited by the CT GC run is seen by a concurrent DNS garbage collector
// run, and then deleted.
// When 'ctGCStart' is later than an alive timestamp, set with MarkAlive, the zombie is
// no longer alive. Thus, this call acts as a gating function for what data is
// returned by GC.
func (zombies *DNSZombieMappings) SetCTGCTime(ctGCStart, estNext time.Time) {
	zombies.Lock()
	defer zombies.Unlock()

	zombies.lastCTGCUpdate = ctGCStart
	zombies.nextCTGCUpdate = estNext
	zombies.ctGCRevision++
}

// NextCTGCUpdate returns the estimated next CT GC time.
func (zombies *DNSZombieMappings) NextCTGCUpdate() time.Time {
	zombies.Lock()
	defer zombies.Unlock()

	return zombies.nextCTGCUpdate
}

// ForceExpire is used to clear zombies irrespective of their alive status.
// Only zombies with DeletePendingAt times before expireLookupBefore are
// considered for deletion. Each name in an zombie is matched against
// nameMatcher (nil is match all) and when an zombie no longer has any valid
// names will it be removed outright.
// Note that all parameters must match, if provided. `time.Time{}` is the
// match-all time parameter.
// expireLookupsBefore requires an zombie to have been enqueued before the
// specified time in order to remove it.
// For example:
//
//	ForceExpire(time.Time{}, 'cilium.io') expires all entries for cilium.io.
//	ForceExpire(time.Now(), 'cilium.io') expires all entries for cilium.io
//	that expired before the current time.
//
// nameMatch will remove that specific DNS name from zombies that include it,
// deleting it when no DNS names remain.
func (zombies *DNSZombieMappings) ForceExpire(expireLookupsBefore time.Time, nameMatch *regexp.Regexp) (namesAffected []string) {
	zombies.Lock()
	defer zombies.Unlock()

	var toDelete []*DNSZombieMapping

	for _, zombie := range zombies.deletes {
		// Do not expire zombies that were enqueued after expireLookupsBefore, but
		// only if the value is non-zero
		if !expireLookupsBefore.IsZero() && zombie.DeletePendingAt.After(expireLookupsBefore) {
			continue
		}

		// A zombie has multiple names, collect the ones that should remain (i.e.
		// do not match nameMatch)
		var newNames []string
		for _, name := range zombie.Names {
			if nameMatch != nil && !nameMatch.MatchString(name) {
				newNames = append(newNames, name)
			} else {
				namesAffected = append(namesAffected, name)
			}
		}
		zombie.Names = newNames

		// Delete the zombie outright if no names remain
		if len(zombie.Names) == 0 {
			toDelete = append(toDelete, zombie)
		}
	}

	// Delete the zombies that are now empty
	for _, zombie := range toDelete {
		delete(zombies.deletes, zombie.IP)
	}

	return namesAffected
}

// ForceExpireByNameIP clears all zombie enties for a given (name, []ip) lookup. Call this
// when learning a new set of A records.
func (zombies *DNSZombieMappings) ForceExpireByNameIP(expireLookupsBefore time.Time, name string, ips ...netip.Addr) {
	zombies.Lock()
	defer zombies.Unlock()

	for _, ip := range ips {
		zombie, ok := zombies.deletes[ip]
		if !ok {
			continue
		}

		if !expireLookupsBefore.IsZero() && zombie.DeletePendingAt.After(expireLookupsBefore) {
			continue
		}

		// Remove the specified name (if extant) and, if it was
		// the last one, delete the entry entirely
		zombie.Names = slices.DeleteFunc(zombie.Names, func(s string) bool { return s == name })
		if len(zombie.Names) == 0 {
			delete(zombies.deletes, ip)
		}
	}
}

// PrefixMatcherFunc is a function passed to (*DNSZombieMappings).DumpAlive,
// called on each zombie to determine whether it should be returned.
type PrefixMatcherFunc func(ip netip.Addr) bool
type NameMatcherFunc func(name string) bool

// DumpAlive returns copies of still-alive zombies matching prefixMatcher.
func (zombies *DNSZombieMappings) DumpAlive(prefixMatcher PrefixMatcherFunc) (alive []*DNSZombieMapping) {
	zombies.Lock()
	defer zombies.Unlock()

	aliveNames := zombies.getAliveNames()
	for _, zombie := range zombies.deletes {
		if alive, _ := zombies.isZombieAlive(zombie, aliveNames); !alive {
			continue
		}
		// only proceed if zombie is alive and the IP matches the CIDR selector
		if prefixMatcher != nil && !prefixMatcher(zombie.IP) {
			continue
		}

		alive = append(alive, zombie.DeepCopy())
	}

	return alive
}

// MarshalJSON encodes DNSZombieMappings into JSON. Only the DNSZombieMapping
// entries are encoded.
func (zombies *DNSZombieMappings) MarshalJSON() ([]byte, error) {
	zombies.Lock()
	defer zombies.Unlock()

	// This hackery avoids exposing DNSZombieMappings.deletes as a public field.
	// The JSON package cannot serialize private fields so we have to make a
	// proxy type here.
	aux := struct {
		Deletes map[netip.Addr]*DNSZombieMapping `json:"deletes,omitempty"`
	}{
		Deletes: zombies.deletes,
	}

	return json.Marshal(aux)
}

// UnmarshalJSON rebuilds a DNSZombieMappings from serialized JSON. It resets
// the AliveAt timestamps, requiring a CT GC cycle to occur before any zombies
// are deleted (by not being marked alive).
// Note: This is destructive to any correct data
func (zombies *DNSZombieMappings) UnmarshalJSON(raw []byte) error {
	zombies.Lock()
	defer zombies.Unlock()

	// This hackery avoids exposing DNSZombieMappings.deletes as a public field.
	// The JSON package cannot deserialize private fields so we have to make a
	// proxy type here.
	aux := struct {
		Deletes map[netip.Addr]*DNSZombieMapping `json:"deletes,omitempty"`
	}{
		Deletes: zombies.deletes,
	}
	if err := json.Unmarshal(raw, &aux); err != nil {
		return err
	}
	zombies.deletes = aux.Deletes

	// Reset the conntrack revision to ensure no deletes happen until we run CT GC again
	for _, zombie := range zombies.deletes {
		zombie.revisionAddedAt = zombies.ctGCRevision
	}
	return nil
}
