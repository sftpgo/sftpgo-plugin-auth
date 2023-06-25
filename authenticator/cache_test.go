// Copyright (C) 2023 Nicola Murino
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

package authenticator

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCache(t *testing.T) {
	c := &authCache{
		cacheTime: 2,
		cache:     make(map[string]cachedUser),
	}
	c.Add("", "")
	c.mu.RLock()
	require.Equal(t, 0, len(c.cache))
	c.mu.RUnlock()

	user1 := "user1"
	user2 := "user2"
	pwd1 := "pwd1"
	pwd2 := "pwd2"

	found, match := c.Check(user1, pwd1)
	require.False(t, found)
	require.False(t, match)

	c.Add(user1, pwd1)
	c.mu.RLock()
	require.Equal(t, 1, len(c.cache))
	cachedAt := c.cache[user1].cachedAt
	c.mu.RUnlock()

	time.Sleep(20 * time.Millisecond)
	c.Add(user1, pwd2)
	c.mu.RLock()
	require.Equal(t, 1, len(c.cache))
	require.Equal(t, cachedAt, c.cache[user1].cachedAt)
	c.mu.RUnlock()

	found, match = c.Check(user1, pwd2)
	require.True(t, found)
	require.False(t, match)
	found, match = c.Check(user1, pwd1)
	require.True(t, found)
	require.True(t, match)
	found, match = c.Check("", "")
	require.False(t, found)
	require.False(t, match)
	found = c.Has("")
	require.False(t, found)
	found = c.Has(user1)
	require.True(t, found)
	found = c.Has(user2)
	require.False(t, found)

	time.Sleep(2 * time.Second)

	c.Add(user2, pwd2)
	c.mu.RLock()
	require.Equal(t, 2, len(c.cache))
	c.mu.RUnlock()

	found = c.Has(user1)
	require.False(t, found)
	found = c.Has(user2)
	require.True(t, found)
	found, match = c.Check(user1, pwd1)
	require.False(t, found)
	require.False(t, match)
	found, match = c.Check(user2, pwd2)
	require.True(t, found)
	require.True(t, match)

	c.cleanup()
	c.mu.RLock()
	require.Equal(t, 1, len(c.cache))
	c.mu.RUnlock()

	found, match = c.Check(user2, pwd2)
	require.True(t, found)
	require.True(t, match)
}

func TestCleanup(t *testing.T) {
	cache = &authCache{
		cacheTime: 2,
		cache:     make(map[string]cachedUser),
	}
	cache.Add("1", "1")
	time.Sleep(2 * time.Second)
	cache.Add("2", "2")
	startCleanupTicker(20 * time.Millisecond)
	assert.Eventually(t, func() bool {
		if !cache.Has("2") {
			return false
		}
		cache.mu.RLock()
		defer cache.mu.RUnlock()

		return len(cache.cache) == 1
	}, 500*time.Millisecond, 100*time.Millisecond)
	stopCleanupTicker()
	cache = nil
}
