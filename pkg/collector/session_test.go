// Copyright 2024 VMware, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package collector

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSessionTemplateAddAndDelete(t *testing.T) {
	const (
		templateID  = 100
		obsDomainID = 0xabcd
		templateTTL = 1 * time.Second
	)
	clock := newFakeClock(time.Now())
	session := newUDPSession("foo")
	session.addTemplate(clock, obsDomainID, templateID, elementsWithValueIPv4, templateTTL)
	// Get a copy of the stored template
	tpl := func() template {
		session.mutex.RLock()
		defer session.mutex.RUnlock()
		return *session.templatesMap[obsDomainID][templateID]
	}()
	require.NotNil(t, tpl.expiryTimer)
	require.True(t, session.deleteTemplate(obsDomainID, templateID))
	// Stop returns false if the timer has already been stopped, which
	// should be done by the call to deleteTemplate.
	assert.False(t, tpl.expiryTimer.Stop())
	// Deleting the template a second time should return false
	assert.False(t, session.deleteTemplate(obsDomainID, templateID))
}

// TestSessionTemplateUpdate checks the behavior of addTemplate when a template is refreshed.
func TestSessionTemplateUpdate(t *testing.T) {
	const (
		templateID  = 100
		obsDomainID = 0xabcd
		templateTTL = 1 * time.Second
	)
	now := time.Now()
	clock := newFakeClock(now)
	session := newUDPSession("foo")
	session.addTemplate(clock, obsDomainID, templateID, elementsWithValueIPv4, templateTTL)
	// Get a copy of the stored template
	getTemplate := func() template {
		session.mutex.RLock()
		defer session.mutex.RUnlock()
		return *session.templatesMap[obsDomainID][templateID]
	}
	tpl := getTemplate()
	require.NotNil(t, tpl.expiryTimer)
	assert.Equal(t, now.Add(templateTTL), tpl.expiryTime)
	// Advance the clock by half the TTL
	clock.Step(500 * time.Millisecond)
	// Template should still be present in map
	_, err := session.getTemplateIEs(obsDomainID, templateID)
	require.NoError(t, err)
	// "Update" the template (template is being refreshed)
	session.addTemplate(clock, obsDomainID, templateID, elementsWithValueIPv4, templateTTL)
	tpl = getTemplate()
	assert.Equal(t, clock.Now().Add(templateTTL), tpl.expiryTime)
	// Advance the clock by half the TTL again, template should still be present
	clock.Step(500 * time.Millisecond)
	_, err = session.getTemplateIEs(obsDomainID, templateID)
	require.NoError(t, err)
	// Advance the clock by half the TTL again, template should be expired
	clock.Step(500 * time.Millisecond)
	_, err = session.getTemplateIEs(obsDomainID, templateID)
	assert.Error(t, err)
}

func BenchmarkAddTemplateUDP(b *testing.B) {
	const (
		templateID  = 100
		templateTTL = 300 * time.Second
	)
	clock := newFakeClock(time.Now())
	obsDomainID := uint32(1)
	session := newUDPSession("foo")
	b.ResetTimer()
	for range b.N {
		session.addTemplate(clock, obsDomainID, 256, elementsWithValueIPv4, templateTTL)
		obsDomainID = (obsDomainID + 1) % 1000
	}
}
