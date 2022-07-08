package main

import (
	"fmt"
	"reflect"
)

type Student struct {
	Name   string
	Age    string
	Gender string
}

func main() {
	var s = Student{
		Name:   "123",
		Age:    "55",
		Gender: "male",
	}
	v := reflect.ValueOf(s)
	for i := 0; i < v.NumField(); i++ {
		fmt.Println(v.Field(i).String())
	}

}
