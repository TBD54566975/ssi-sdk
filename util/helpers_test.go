package util

import (
	"testing"

	"github.com/stretchr/testify/assert"
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
		data := []interface{}{"hello"}
		res, err := ArrayInterfaceToStr(data)
		assert.NoError(tt, err)
		assert.True(tt, len(res) == 1)
		assert.True(tt, res[0] == data[0])
	})

	t.Run("multi value string array", func(tt *testing.T) {
		data := []interface{}{"hello", "goodbye"}
		res, err := ArrayInterfaceToStr(data)
		assert.NoError(tt, err)
		assert.True(tt, len(res) == 2)
	})

	t.Run("non string array", func(tt *testing.T) {
		bad := []interface{}{2}
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
