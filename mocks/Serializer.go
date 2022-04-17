// Code generated by mockery v2.10.1. DO NOT EDIT.

package mocks

import (
	context "context"

	domain "github.com/fgmaia/securitycodescanner/internal/domain"
	mock "github.com/stretchr/testify/mock"
)

// Serializer is an autogenerated mock type for the Serializer type
type Serializer struct {
	mock.Mock
}

// Execute provides a mock function with given fields: ctx, result, file
func (_m *Serializer) Execute(ctx context.Context, result domain.ScanResult, file string) error {
	ret := _m.Called(ctx, result, file)

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, domain.ScanResult, string) error); ok {
		r0 = rf(ctx, result, file)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}