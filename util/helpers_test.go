package util

import (
	"testing"
	"time"

	"github.com/piprate/json-gold/ld"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestInterfaceToStrings(t *testing.T) {
	t.Run("simple string", func(tt *testing.T) {
		data := "hello"
		res, err := InterfaceToStrings(data)
		assert.NoError(tt, err)
		assert.True(tt, len(res) == 1)
		assert.True(tt, res[0] == data)
	})

	t.Run("simple string array", func(tt *testing.T) {
		data := []string{"hello"}
		res, err := InterfaceToStrings(data)
		assert.NoError(tt, err)
		assert.True(tt, len(res) == 1)
		assert.True(tt, res[0] == data[0])
	})

	t.Run("multi value string array", func(tt *testing.T) {
		data := []string{"hello", "goodbye"}
		res, err := InterfaceToStrings(data)
		assert.NoError(tt, err)
		assert.True(tt, len(res) == 2)
		assert.EqualValues(tt, data, res)
	})

	t.Run("non string value", func(tt *testing.T) {
		bad := 2
		_, err := InterfaceToStrings(bad)
		assert.Error(tt, err)
	})

	t.Run("non string array", func(tt *testing.T) {
		bad := []int{2}
		_, err := InterfaceToStrings(bad)
		assert.Error(tt, err)
	})
}

func TestArrayInterfaceToStr(t *testing.T) {
	t.Run("simple string array", func(tt *testing.T) {
		data := []any{"hello"}
		res, err := ArrayInterfaceToStr(data)
		assert.NoError(tt, err)
		assert.True(tt, len(res) == 1)
		assert.True(tt, res[0] == data[0])
	})

	t.Run("multi value string array", func(tt *testing.T) {
		data := []any{"hello", "goodbye"}
		res, err := ArrayInterfaceToStr(data)
		assert.NoError(tt, err)
		assert.True(tt, len(res) == 2)
	})

	t.Run("non string array", func(tt *testing.T) {
		bad := []any{2}
		_, err := ArrayInterfaceToStr(bad)
		assert.Error(tt, err)
	})
}

func TestMergeUniqueValues(t *testing.T) {
	t.Run("No union", func(tt *testing.T) {
		a := []string{"a", "b", "c"}
		b := []string{"d", "e", "f"}
		res := MergeUniqueValues(a, b)
		assert.True(tt, len(res) == len(a)+len(b))
	})

	t.Run("All overlap", func(tt *testing.T) {
		a := []string{"a", "b", "c"}
		b := []string{"a", "b", "c"}
		res := MergeUniqueValues(a, b)
		assert.True(tt, len(res) == len(a))
		assert.EqualValues(tt, a, res)
	})

	t.Run("Some overlap", func(tt *testing.T) {
		a := []string{"a", "b", "c"}
		b := []string{"c", "d", "e"}
		res := MergeUniqueValues(a, b)
		assert.True(tt, len(res) == len(a)+2)
	})
}

func TestLDProcessor(t *testing.T) {
	testJSONDLContextURLStr := "http://schema.org/"
	ldProcessor, err := NewLDProcessor()
	require.NoError(t, err)

	t.Run("caching document loader", func(tt *testing.T) {
		numOfLoads := 5
		nonCachedLoader := ld.NewDefaultDocumentLoader(nil)
		t0 := time.Now()
		for i := 0; i < numOfLoads; i++ {
			doc, err := nonCachedLoader.LoadDocument(testJSONDLContextURLStr)
			assert.NoError(tt, err)
			assert.NotNil(tt, doc)
		}
		dtNonCached := time.Now().Sub(t0)
		tt.Logf("non-cached document loader for %d tests dt: %v\n", numOfLoads, dtNonCached)

		ldProcessor, err := NewLDProcessor()
		require.NoError(tt, err)
		t1 := time.Now()
		for i := 0; i < numOfLoads; i++ {
			doc, err := ldProcessor.DocumentLoader.LoadDocument(testJSONDLContextURLStr)
			assert.NoError(tt, err)
			assert.NotNil(tt, doc)
		}
		dtCached := time.Now().Sub(t1)
		tt.Logf("caching document loader for %d tests dt: %v\n", numOfLoads, dtCached)

		assert.True(tt, dtNonCached/dtCached > 2.0)
	})

	t.Run("get context from map", func(tt *testing.T) {
		contextMap := map[string]any{
			"dc": "http://purl.org/dc/elements/1.1/",
			"ex": "http://example.org/vocab#",
			"ex:contains": map[string]any{
				"@type": "@id",
			},
		}

		activeCtx, err := ldProcessor.GetContextFromMap(contextMap)
		// expected activeCtx output is &{values:map[@base: processingMode:json-ld-1.1] options:0xc0001288f0 termDefinitions:map[dc:map[@id:http://purl.org/dc/elements/1.1/ @reverse:false _prefix:true] ex:map[@id:http://example.org/vocab# @reverse:false _prefix:true] ex:contains:map[@id:http://example.org/vocab#contains @reverse:false @type:@id]] inverse:map[] protected:map[] previousContext:<nil>}
		assert.NoError(tt, err)
		assert.NotNil(tt, activeCtx)
	})
}
