package goscan

import (
	"go/ast"
	"go/constant"
	"go/types"
	"strconv"

	"cadi/internal/inventory"
	"cadi/internal/scope"

	"golang.org/x/tools/go/packages"
)

type declarationProject struct {
	root       string
	exclusions []string
	owners     map[ast.Expr]*packages.Package
	resolvers  map[*packages.Package]*declarationValues
	returns    map[*types.Func]ast.Expr
	fields     map[*types.Var][]inventory.ParameterEvidence
}

func newDeclarationProject(root string, loaded []*packages.Package, exclusions []string) *declarationProject {
	project := &declarationProject{
		root: root, exclusions: exclusions, owners: map[ast.Expr]*packages.Package{},
		resolvers: map[*packages.Package]*declarationValues{}, returns: map[*types.Func]ast.Expr{},
		fields: map[*types.Var][]inventory.ParameterEvidence{},
	}
	mutable := map[types.Object]bool{}
	for _, pkg := range loaded {
		resolver := newDeclarationValues(pkg)
		resolver.project = project
		project.resolvers[pkg] = resolver
		for object := range resolver.mutable {
			mutable[object] = true
		}
		for _, file := range pkg.Syntax {
			ast.Inspect(file, func(node ast.Node) bool {
				if expression, ok := node.(ast.Expr); ok {
					project.owners[expression] = pkg
				}
				if node == nil {
					return true
				}
				position := pkg.Fset.PositionFor(node.Pos(), false)
				if !inside(root, position.Filename) || scope.PathExcluded(root, position.Filename, exclusions) {
					return false
				}
				switch node := node.(type) {
				case *ast.FuncDecl:
					function, ok := pkg.TypesInfo.Defs[node.Name].(*types.Func)
					if !ok || node.Recv != nil || node.Body == nil || len(node.Body.List) != 1 {
						break
					}
					signature, ok := function.Type().(*types.Signature)
					if !ok || signature.Params().Len() != 0 || signature.Results().Len() != 1 || signature.TypeParams().Len() != 0 {
						break
					}
					if ret, ok := node.Body.List[0].(*ast.ReturnStmt); ok && len(ret.Results) == 1 {
						project.returns[function] = ret.Results[0]
					}
				case *ast.CompositeLit:
					project.recordFields(pkg, node)
				}
				return true
			})
		}
	}
	for _, resolver := range project.resolvers {
		resolver.mutable = mutable
	}
	return project
}

func (p *declarationProject) recordFields(pkg *packages.Package, literal *ast.CompositeLit) {
	for _, element := range literal.Elts {
		field, ok := element.(*ast.KeyValueExpr)
		if !ok {
			continue
		}
		name, ok := field.Key.(*ast.Ident)
		if !ok {
			continue
		}
		object, ok := pkg.TypesInfo.Uses[name].(*types.Var)
		if !ok || !object.IsField() {
			continue
		}
		value := pkg.TypesInfo.Types[field.Value].Value
		if value == nil || value.Kind() != constant.Int {
			continue
		}
		number, known := constant.Int64Val(value)
		if !known {
			continue
		}
		position := pkg.Fset.PositionFor(field.Value.Pos(), false)
		p.fields[object] = append(p.fields[object], inventory.ParameterEvidence{
			Value: strconv.FormatInt(number, 10), Basis: "field-initializer",
			Location: relative(p.root, position.Filename), Line: position.Line,
			Symbol:     types.TypeString(pkg.TypesInfo.TypeOf(literal), nil) + "." + object.Name(),
			Limitation: "explicit source initializer only; zero values, mutations, and external constructions are not bounded",
		})
	}
}

func (p *declarationProject) resolver(expression ast.Expr) *declarationValues {
	return p.resolvers[p.owners[expression]]
}

func (p *declarationProject) fact(name, value string, expression ast.Expr) inventory.ParameterEvidence {
	fact := inventory.ParameterEvidence{
		Name: name, Value: value, Basis: "declared-policy-initializer",
		Limitation: "declared configuration only; exported mutable policy may change before use",
	}
	if owner := p.owners[expression]; owner != nil {
		position := owner.Fset.PositionFor(expression.Pos(), false)
		fact.Location, fact.Line = relative(p.root, position.Filename), position.Line
	}
	return fact
}
