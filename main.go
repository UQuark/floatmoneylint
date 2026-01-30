package main

import (
	"github.com/UQuark/floatmoneylint/lib"
	"golang.org/x/tools/go/analysis"
)

func New(settings any) ([]*analysis.Analyzer, error) {
	plugin, err := lib.New(settings)
	if err != nil {
		return nil, err
	}
	return plugin.BuildAnalyzers()
}
