package pipeline

import "container/list"

// lru is a bounded map evicting the least recently put entry. Not safe for
// concurrent use: only the writer goroutine touches it.
type lru[K comparable, V any] struct {
	max     int
	order   *list.List // front = most recent
	items   map[K]*list.Element
	evicted func()
}

type lruEntry[K comparable, V any] struct {
	key K
	val V
}

func newLRU[K comparable, V any](max int, evicted func()) *lru[K, V] {
	return &lru[K, V]{max: max, order: list.New(), items: make(map[K]*list.Element), evicted: evicted}
}

func (l *lru[K, V]) put(key K, val V) {
	if el, ok := l.items[key]; ok {
		el.Value = lruEntry[K, V]{key, val}
		l.order.MoveToFront(el)
		return
	}
	if l.order.Len() >= l.max {
		oldest := l.order.Back()
		l.order.Remove(oldest)
		delete(l.items, oldest.Value.(lruEntry[K, V]).key)
		l.evicted()
	}
	l.items[key] = l.order.PushFront(lruEntry[K, V]{key, val})
}

func (l *lru[K, V]) get(key K) (V, bool) {
	el, ok := l.items[key]
	if !ok {
		var zero V
		return zero, false
	}
	return el.Value.(lruEntry[K, V]).val, true
}

// take returns and removes key.
func (l *lru[K, V]) take(key K) (V, bool) {
	val, ok := l.get(key)
	if ok {
		l.order.Remove(l.items[key])
		delete(l.items, key)
	}
	return val, ok
}

// pruneOldest removes entries from the oldest while stale holds, returns the count.
func (l *lru[K, V]) pruneOldest(stale func(V) bool) int {
	n := 0
	for el := l.order.Back(); el != nil && stale(el.Value.(lruEntry[K, V]).val); el = l.order.Back() {
		l.order.Remove(el)
		delete(l.items, el.Value.(lruEntry[K, V]).key)
		n++
	}
	return n
}

func (l *lru[K, V]) len() int { return l.order.Len() }
