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
	"sync"
	"time"

	"github.com/sftpgo/sftpgo-plugin-auth/logger"
)

var (
	cache         *authCache
	cleanupTicker *time.Ticker
	cleanupDone   chan bool
)

type cachedUser struct {
	username string
	password string
	cachedAt int64
}

type authCache struct {
	cacheTime int
	mu        sync.RWMutex
	cache     map[string]cachedUser
}

func (c *authCache) Add(username, password string) {
	if username == "" || password == "" {
		return
	}

	c.mu.RLock()
	if creds, ok := c.cache[username]; ok {
		if creds.cachedAt > c.getExpiration() {
			c.mu.RUnlock()
			return
		}
	}
	c.mu.RUnlock()

	c.mu.Lock()
	defer c.mu.Unlock()

	u := cachedUser{
		username: username,
		password: password,
		cachedAt: time.Now().UnixMilli(),
	}
	c.cache[username] = u
}

func (c *authCache) Check(username, password string) (bool, bool) {
	if username == "" || password == "" {
		return false, false
	}

	c.mu.RLock()
	defer c.mu.RUnlock()

	creds, ok := c.cache[username]
	if !ok {
		return false, false
	}
	if creds.cachedAt < c.getExpiration() {
		return false, false
	}
	match := creds.password == password
	return true, match
}

func (c *authCache) Has(username string) bool {
	if username == "" {
		return false
	}
	c.mu.RLock()
	defer c.mu.RUnlock()

	creds, ok := c.cache[username]
	if !ok {
		return false
	}
	return creds.cachedAt >= c.getExpiration()
}

func (c *authCache) getExpiration() int64 {
	return time.Now().Add(-time.Duration(c.cacheTime) * time.Second).UnixMilli()
}

func (c *authCache) cleanup() {
	c.mu.Lock()
	defer c.mu.Unlock()

	timeLimit := c.getExpiration()
	for k, v := range c.cache {
		if v.cachedAt < timeLimit {
			delete(c.cache, k)
		}
	}
	logger.AppLogger.Debug("cleanup cache finished", "size", len(c.cache))
}

func startCleanupTicker(duration time.Duration) {
	stopCleanupTicker()
	cleanupTicker = time.NewTicker(duration)
	cleanupDone = make(chan bool)

	go func() {
		for {
			select {
			case <-cleanupDone:
				return
			case <-cleanupTicker.C:
				cache.cleanup()
			}
		}
	}()
}

func stopCleanupTicker() {
	if cleanupTicker != nil {
		cleanupTicker.Stop()
		cleanupDone <- true
		cleanupTicker = nil
	}
}
