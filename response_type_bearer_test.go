package oauth2_test

import (
	"fmt"
	"github.com/tsingsun/go-oauth2"
	"reflect"
	"testing"
)

func TestResponseType_New(t *testing.T) {
	rtIns := defaultService.Options().DefaultResponseType
	rtType := reflect.TypeOf(rtIns)
	ptr := reflect.New(rtType.Elem())
	val := ptr.Elem()
	if _, ok := val.Interface().(oauth2.BearerTokenResponse); !ok {
		t.Error()
	}
}

func TestReflect(t *testing.T) {
	type Product struct {
		Name  string
		Price string
	}

	var product Product
	productType := reflect.TypeOf(product)       // this type of this variable is reflect.Type
	productPointer := reflect.New(productType)   // this type of this variable is reflect.Value.
	productValue := productPointer.Elem()        // this type of this variable is reflect.Value.
	productInterface := productValue.Interface() // this type of this variable is interface{}
	product2 := productInterface.(Product)       // this type of this variable is product

	product2.Name = "Toothbrush"
	product2.Price = "2.50"

	fmt.Println(product2.Name)
	fmt.Println(product2.Price)
}
