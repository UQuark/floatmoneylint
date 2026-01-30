package lib

import (
	"fmt"
	"go/ast"
	"go/token"
	"slices"
	"strconv"
	"strings"

	"github.com/golangci/plugin-module-register/register"
	"golang.org/x/tools/go/analysis"
)

func init() {
	register.Plugin("floatmoney", New)
}

type Settings struct {
	Names []string `json:"names"`
}

type FloatMoney struct {
	settings Settings
}

func New(settings any) (register.LinterPlugin, error) {
	// The configuration type will be map[string]any or []interface, it depends on your configuration.
	// You can use https://github.com/go-viper/mapstructure to convert map to struct.

	s, err := register.DecodeSettings[Settings](settings)
	if err != nil {
		return nil, err
	}

	return &FloatMoney{settings: s}, nil
}

func (f *FloatMoney) BuildAnalyzers() ([]*analysis.Analyzer, error) {
	return []*analysis.Analyzer{
		{
			Name: "floatmoney",
			Doc:  "finds suspicious float variables with money-related names",
			Run:  f.run,
		},
	}, nil
}

func (f *FloatMoney) GetLoadMode() string {
	// NOTE: the mode can be `register.LoadModeSyntax` or `register.LoadModeTypesInfo`.
	//- `register.LoadModeSyntax`: if the linter doesn't use types information.
	//- `register.LoadModeTypesInfo`: if the linter uses types information.

	return register.LoadModeSyntax
}

func (f *FloatMoney) run(pass *analysis.Pass) (any, error) {
	for _, file := range pass.Files {
		ast.Inspect(file, func(n ast.Node) bool {
			switch n := n.(type) {
			case *ast.GenDecl:
				switch n.Tok {
				case token.VAR:
					fallthrough
				case token.CONST:
					for _, spec := range n.Specs {
						spec := spec.(*ast.ValueSpec)
						var expr ast.Expr = nil
						ident := getInnerFloat(spec.Type)
						if ident != nil {
							expr = ident
						} else {
							for _, value := range spec.Values {
								if isFloatExpr(value) {
									expr = value
									break
								}
							}
							if expr == nil {
								return true
							}
						}
						names := make([]string, 0)
						for _, name := range spec.Names {
							names = append(names, name.Name)
						}
						if intersects(f.settings.Names, names) {
							switch expr := expr.(type) {
							case *ast.Ident:
								pass.Report(analysis.Diagnostic{
									Pos:      expr.Pos(),
									End:      expr.End(),
									Category: "floatmoney",
									Message: fmt.Sprintf(
										"a declaration with a suspicious money-related name has %s type. "+
											"use https://github.com/shopspring/decimal instead",
										expr.Name,
									),
									Related: nil,
								})
							case *ast.BasicLit:
								pass.Report(analysis.Diagnostic{
									Pos:      expr.Pos(),
									End:      expr.End(),
									Category: "floatmoney",
									Message: fmt.Sprintf(
										"a declaration with a suspicious money-related name has a float value of \"%s\". "+
											"use https://github.com/shopspring/decimal instead",
										expr.Value,
									),
									Related: nil,
								})
							}
						}
					}
				case token.TYPE:
					for _, spec := range n.Specs {
						spec := spec.(*ast.TypeSpec)
						if !isSuspicious(f.settings.Names, spec.Name.Name) {
							return true
						}
						switch typ := spec.Type.(type) {
						case *ast.Ident:
							typ = getInnerFloat(typ)
							if typ != nil {
								pass.Report(analysis.Diagnostic{
									Pos:      typ.Pos(),
									End:      typ.End(),
									Category: "floatmoney",
									Message: fmt.Sprintf(
										"a type with a suspicious money-related name is an alias to %s. "+
											"use https://github.com/shopspring/decimal instead",
										typ.Name,
									),
									Related: nil,
								})
							}
						case *ast.ArrayType:
							innerFloat := getInnerFloat(typ)
							if typ != nil {
								pass.Report(analysis.Diagnostic{
									Pos:      typ.Pos(),
									End:      typ.End(),
									Category: "floatmoney",
									Message: fmt.Sprintf(
										"a type with a suspicious money-related name is an alias to %s. "+
											"use https://github.com/shopspring/decimal instead",
										innerFloat.Name,
									),
									Related: nil,
								})
							}
						case *ast.StructType:
							for _, field := range typ.Fields.List {
								typ := getInnerFloat(field.Type)
								if typ == nil {
									return true
								}
								pass.Report(analysis.Diagnostic{
									Pos:      typ.Pos(),
									End:      typ.End(),
									Category: "floatmoney",
									Message: fmt.Sprintf(
										"a struct type with a suspicious money-related name has a field of %s type. "+
											"use https://github.com/shopspring/decimal instead",
										typ.Name,
									),
									Related: nil,
								})
							}
						}
					}
				default:
					return true
				}

			case *ast.FuncDecl:
				if n.Type == nil {
					return true
				}
				if n.Type.Params != nil {
					for _, field := range n.Type.Params.List {
						typ := getInnerFloat(field.Type)
						if typ == nil {
							return true
						}
						names := make([]string, 0)
						for _, name := range field.Names {
							names = append(names, name.Name)
						}
						if isSuspicious(f.settings.Names, n.Name.Name) || intersects(f.settings.Names, names) {
							pass.Report(analysis.Diagnostic{
								Pos:      typ.Pos(),
								End:      typ.End(),
								Category: "floatmoney",
								Message: fmt.Sprintf(
									"a function with a suspicious money-related name has a parameter of %s type. "+
										"use https://github.com/shopspring/decimal instead",
									typ.Name,
								),
								Related: nil,
							})
						}
					}
				}

				if n.Type.Results != nil {
					for _, field := range n.Type.Results.List {
						typ := getInnerFloat(field.Type)
						if typ == nil {
							return true
						}
						names := make([]string, 0)
						for _, name := range field.Names {
							names = append(names, name.Name)
						}
						if isSuspicious(f.settings.Names, n.Name.Name) || intersects(f.settings.Names, names) {
							pass.Report(analysis.Diagnostic{
								Pos:      typ.Pos(),
								End:      typ.End(),
								Category: "floatmoney",
								Message: fmt.Sprintf(
									"a function with a suspicious money-related name has a return value of %s type. "+
										"use https://github.com/shopspring/decimal instead",
									typ.Name,
								),
								Related: nil,
							})
						}
					}
				}

			case *ast.Field:
				typ := getInnerFloat(n.Type)
				if typ == nil {
					return true
				}

				names := make([]string, 0)
				for _, name := range n.Names {
					names = append(names, name.Name)
				}
				if n.Tag != nil {
					names = append(names, n.Tag.Value)
				}

				if intersects(f.settings.Names, names) {
					pass.Report(analysis.Diagnostic{
						Pos:      typ.Pos(),
						End:      typ.End(),
						Category: "floatmoney",
						Message: fmt.Sprintf(
							"a field with a suspicious money-related name has %s type. "+
								"use https://github.com/shopspring/decimal instead",
							typ.Name,
						),
						Related: nil,
					})
				}
			}

			return true
		})
	}

	return nil, nil
}

func isFloatTypeName(typ string) bool {
	return slices.Contains[[]string, string]([]string{"float32", "float64"}, typ)
}

func isSuspicious(target []string, name string) bool {
	for _, t := range target {
		if strings.Contains(strings.ToLower(name), strings.ToLower(t)) {
			return true
		}
	}
	return false
}

func intersects(target []string, search []string) bool {
	for _, s := range search {
		if isSuspicious(target, s) {
			return true
		}
	}
	return false
}

func getInnerFloat(typ ast.Expr) *ast.Ident {
	switch typ := typ.(type) {
	case *ast.Ident:
		if isFloatTypeName(typ.Name) {
			return typ
		}
	case *ast.ArrayType:
		if eltTyp, ok := typ.Elt.(*ast.Ident); ok {
			if isFloatTypeName(eltTyp.Name) {
				return eltTyp
			}
		}
	}
	return nil
}

func isFloatExpr(expr ast.Expr) bool {
	switch expr := expr.(type) {
	case *ast.BasicLit:
		_, err := strconv.ParseInt(expr.Value, 0, 64)
		if err == nil {
			return false
		}
		_, err = strconv.ParseFloat(expr.Value, 64)
		if err == nil {
			return true
		}
		return false
	default:
		return false
	}
}
