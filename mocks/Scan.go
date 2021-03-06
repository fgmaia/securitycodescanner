// Code generated by mockery v2.10.1. DO NOT EDIT.

package mocks

import (
	context "context"

	customtypes "github.com/fgmaia/securitycodescanner/internal/customtypes"
	domain "github.com/fgmaia/securitycodescanner/internal/domain"

	mock "github.com/stretchr/testify/mock"
)

// Scan is an autogenerated mock type for the Scan type
type Scan struct {
	mock.Mock
}

// Execute provides a mock function with given fields: ctx, file, data
func (_m *Scan) Execute(ctx context.Context, file string, data string) ([]domain.ScanFileOutput, error) {
	ret := _m.Called(ctx, file, data)

	var r0 []domain.ScanFileOutput
	if rf, ok := ret.Get(0).(func(context.Context, string, string) []domain.ScanFileOutput); ok {
		r0 = rf(ctx, file, data)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]domain.ScanFileOutput)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context, string, string) error); ok {
		r1 = rf(ctx, file, data)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// GetType provides a mock function with given fields:
func (_m *Scan) GetType() customtypes.ScanType {
	ret := _m.Called()

	var r0 customtypes.ScanType
	if rf, ok := ret.Get(0).(func() customtypes.ScanType); ok {
		r0 = rf()
	} else {
		r0 = ret.Get(0).(customtypes.ScanType)
	}

	return r0
}
