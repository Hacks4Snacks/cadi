package goscan

import (
	"go/ast"
	"go/constant"
	"go/token"
	"go/types"

	"ciphertrail/internal/inventory"

	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/go/ssa"
)

type declarationValues struct {
	pkg         *packages.Package
	initial     map[types.Object]ast.Expr
	assignments map[types.Object]int
	mutable     map[types.Object]bool
	project     *declarationProject
	declared    bool
}

func newDeclarationValues(pkg *packages.Package) *declarationValues {
	v := &declarationValues{pkg: pkg, initial: map[types.Object]ast.Expr{}, assignments: map[types.Object]int{}, mutable: map[types.Object]bool{}}
	record := func(identifier *ast.Ident, expression ast.Expr) {
		object := pkg.TypesInfo.ObjectOf(identifier)
		if object != nil {
			v.assignments[object]++
			v.initial[object] = expression
		}
	}
	for _, file := range pkg.Syntax {
		ast.Inspect(file, func(node ast.Node) bool {
			switch node := node.(type) {
			case *ast.ValueSpec:
				for i, identifier := range node.Names {
					var expression ast.Expr
					if len(node.Values) == len(node.Names) {
						expression = node.Values[i]
					}
					record(identifier, expression)
				}
			case *ast.AssignStmt:
				for i, lhs := range node.Lhs {
					if identifier, ok := lhs.(*ast.Ident); ok {
						var expression ast.Expr
						if len(node.Lhs) == len(node.Rhs) {
							expression = node.Rhs[i]
						}
						record(identifier, expression)
					} else if object := v.rootObject(lhs); object != nil {
						v.mutable[object] = true
					}
				}
			case *ast.IncDecStmt:
				if object := v.rootObject(node.X); object != nil {
					v.mutable[object] = true
				}
			case *ast.CallExpr:
				if pkg.TypesInfo.Types[node.Fun].IsType() || v.copyAppend(node) {
					return true
				}
				if selector, ok := node.Fun.(*ast.SelectorExpr); ok {
					if object := v.rootObject(selector.X); object != nil {
						v.mutable[object] = true
					}
				}
				for _, argument := range node.Args {
					if object := v.rootObject(argument); object != nil {
						v.mutable[object] = true
					}
				}
			case *ast.ReturnStmt:
				for _, expression := range node.Results {
					if object := v.rootObject(expression); object != nil {
						if resultType := pkg.TypesInfo.TypeOf(expression); resultType != nil {
							if _, pointer := resultType.Underlying().(*types.Pointer); pointer {
								v.mutable[object] = true
							}
						}
					}
				}
			}
			return true
		})
	}
	// Reference-valued globals are resolved only through value-copy reads.
	// Other uses can leak an alias beyond the mutations visible in this package.
	for _, file := range pkg.Syntax {
		var parents []ast.Node
		ast.Inspect(file, func(node ast.Node) bool {
			if node == nil {
				parents = parents[:len(parents)-1]
				return true
			}
			if identifier, ok := node.(*ast.Ident); ok && len(parents) > 0 {
				object, variable := pkg.TypesInfo.Uses[identifier].(*types.Var)
				if variable && object.Parent() == pkg.Types.Scope() {
					reference := false
					switch object.Type().Underlying().(type) {
					case *types.Pointer, *types.Slice, *types.Map:
						reference = true
					}
					if reference {
						allowed := false
						switch parent := parents[len(parents)-1].(type) {
						case *ast.StarExpr:
							allowed = parent.X == identifier
						case *ast.CallExpr:
							allowed = v.copyAppend(parent) && parent.Args[1] == identifier
						}
						if !allowed {
							v.mutable[object] = true
						}
					}
				}
			}
			parents = append(parents, node)
			return true
		})
	}
	// A write through a pointer alias invalidates the original too. Dereferencing
	// a struct into a local value is a copy, not a reverse mutation relationship.
	var pending []types.Object
	for object := range v.mutable {
		pending = append(pending, object)
	}
	for len(pending) > 0 {
		object := pending[len(pending)-1]
		pending = pending[:len(pending)-1]
		if _, pointer := object.Type().Underlying().(*types.Pointer); !pointer {
			continue
		}
		if initial := v.initial[object]; initial != nil {
			if _, copy := ast.Unparen(initial).(*ast.StarExpr); copy {
				continue
			}
			if original := v.rootObject(initial); original != nil && !v.mutable[original] {
				v.mutable[original] = true
				pending = append(pending, original)
			}
		}
	}
	return v
}

func (v *declarationValues) rootObject(expression ast.Expr) types.Object {
	switch expression := expression.(type) {
	case *ast.Ident:
		object := v.pkg.TypesInfo.ObjectOf(expression)
		if _, variable := object.(*types.Var); variable {
			return object
		}
	case *ast.ParenExpr:
		return v.rootObject(expression.X)
	case *ast.UnaryExpr:
		return v.rootObject(expression.X)
	case *ast.StarExpr:
		return v.rootObject(expression.X)
	case *ast.SelectorExpr:
		if object, ok := v.pkg.TypesInfo.ObjectOf(expression.Sel).(*types.Var); ok && !object.IsField() {
			return object
		}
		return v.rootObject(expression.X)
	case *ast.IndexExpr:
		return v.rootObject(expression.X)
	case *ast.SliceExpr:
		return v.rootObject(expression.X)
	}
	return nil
}

func (v *declarationValues) copyAppend(call *ast.CallExpr) bool {
	identifier, ok := call.Fun.(*ast.Ident)
	if !ok || v.pkg.TypesInfo.ObjectOf(identifier) != types.Universe.Lookup("append") || len(call.Args) != 2 || !call.Ellipsis.IsValid() {
		return false
	}
	if empty, ok := call.Args[0].(*ast.CompositeLit); ok && len(empty.Elts) == 0 {
		_, slice := v.pkg.TypesInfo.TypeOf(empty).Underlying().(*types.Slice)
		return slice
	}
	conversion, ok := call.Args[0].(*ast.CallExpr)
	if !ok || !v.pkg.TypesInfo.Types[conversion.Fun].IsType() || len(conversion.Args) != 1 {
		return false
	}
	_, slice := v.pkg.TypesInfo.TypeOf(conversion).Underlying().(*types.Slice)
	nilValue, ok := conversion.Args[0].(*ast.Ident)
	return slice && ok && v.pkg.TypesInfo.ObjectOf(nilValue) == types.Universe.Lookup("nil")
}

func (v *declarationValues) resolve(expression ast.Expr, seen map[types.Object]bool, depth int) ast.Expr {
	if expression == nil || depth > 16 {
		return nil
	}
	if v.project != nil {
		if owner := v.project.resolver(expression); owner != nil && owner.pkg != v.pkg {
			context := *owner
			context.declared = v.declared
			return context.resolve(expression, seen, depth+1)
		}
	}
	switch value := expression.(type) {
	case *ast.ParenExpr:
		return v.resolve(value.X, seen, depth+1)
	case *ast.StarExpr:
		return v.resolve(value.X, seen, depth+1)
	case *ast.UnaryExpr:
		if value.Op == token.AND {
			return v.resolve(value.X, seen, depth+1)
		}
	case *ast.Ident:
		object := v.pkg.TypesInfo.ObjectOf(value)
		if _, variable := object.(*types.Var); variable {
			if seen[object] || v.assignments[object] != 1 || v.mutable[object] ||
				object.Parent() == v.pkg.Types.Scope() && object.Exported() && !v.declared {
				return nil
			}
			seen[object] = true
			defer delete(seen, object)
			return v.resolve(v.initial[object], seen, depth+1)
		}
	case *ast.CallExpr:
		if v.copyAppend(value) {
			return v.resolve(value.Args[1], seen, depth+1)
		}
		if v.project != nil && len(value.Args) == 0 {
			var object types.Object
			switch function := value.Fun.(type) {
			case *ast.Ident:
				object = v.pkg.TypesInfo.ObjectOf(function)
			case *ast.SelectorExpr:
				object = v.pkg.TypesInfo.ObjectOf(function.Sel)
			}
			if function, ok := object.(*types.Func); ok && !seen[function] {
				if returned := v.project.returns[function]; returned != nil {
					seen[function] = true
					defer delete(seen, function)
					return v.resolve(returned, seen, depth+1)
				}
			}
		}
	}
	return expression
}

func (v *declarationValues) expression(expression ast.Expr) ast.Expr {
	return v.resolve(expression, map[types.Object]bool{}, 0)
}

func (v *declarationValues) literal(expression ast.Expr) *ast.CompositeLit {
	literal, _ := v.expression(expression).(*ast.CompositeLit)
	return literal
}

func (v *declarationValues) scalar(expression ast.Expr) constant.Value {
	expression = v.expression(expression)
	if v.project != nil {
		if owner := v.project.resolver(expression); owner != nil {
			return owner.pkg.TypesInfo.Types[expression].Value
		}
	}
	return v.pkg.TypesInfo.Types[expression].Value
}

func declarationFields(literal *ast.CompositeLit) map[string]ast.Expr {
	fields := map[string]ast.Expr{}
	if literal != nil {
		for _, element := range literal.Elts {
			if item, ok := element.(*ast.KeyValueExpr); ok {
				if name, ok := item.Key.(*ast.Ident); ok {
					fields[name.Name] = item.Value
				}
			}
		}
	}
	return fields
}

type values struct {
	callers map[*ssa.Function][]*ssa.CallCommon
	escaped map[*ssa.Function]bool
	project *declarationProject
}

func newValues(functions []*ssa.Function, project *declarationProject) *values {
	v := &values{callers: map[*ssa.Function][]*ssa.CallCommon{}, escaped: map[*ssa.Function]bool{}, project: project}
	for _, function := range functions {
		for _, block := range function.Blocks {
			for _, instruction := range block.Instrs {
				call, calling := instruction.(ssa.CallInstruction)
				if calling {
					if callee := call.Common().StaticCallee(); callee != nil {
						v.callers[callee] = append(v.callers[callee], call.Common())
					}
				}
				for _, operand := range instruction.Operands(nil) {
					if operand == nil || *operand == nil {
						continue
					}
					if target, ok := (*operand).(*ssa.Function); ok {
						if !calling || operand != &call.Common().Value {
							v.escaped[target] = true
						}
					}
				}
			}
		}
	}
	return v
}

func (v *values) declaredIntegers(value ssa.Value) []inventory.ParameterEvidence {
	var aggregate types.Type
	var index int
	switch value := value.(type) {
	case *ssa.Field:
		aggregate, index = value.X.Type(), value.Field
	case *ssa.UnOp:
		if field, ok := value.X.(*ssa.FieldAddr); ok && value.Op == token.MUL {
			aggregate, index = field.X.Type(), field.Field
		}
	}
	if aggregate == nil || v.project == nil {
		return nil
	}
	aggregate = types.Unalias(aggregate)
	if pointer, ok := aggregate.(*types.Pointer); ok {
		aggregate = pointer.Elem()
	}
	if structure, ok := aggregate.Underlying().(*types.Struct); ok && index >= 0 && index < structure.NumFields() {
		return v.project.fields[structure.Field(index)]
	}
	return nil
}
func (v *values) integer(value ssa.Value) (int64, bool) {
	number := v.resolve(value, map[ssa.Value]bool{}, 0)
	if number == nil || number.Kind() != constant.Int {
		return 0, false
	}
	return constant.Int64Val(number)
}

// constructorAPI identifies a visible factory, without executing it or assuming
// its argument values. Conflicting branches, fields, and opaque wrappers stay unknown.
func constructorAPI(value ssa.Value) apiIdentity {
	seen := map[ssa.Value]bool{}
	var resolve func(ssa.Value, int) apiIdentity
	resolve = func(value ssa.Value, depth int) apiIdentity {
		if value == nil || depth > 16 || seen[value] {
			return apiIdentity{}
		}
		seen[value] = true
		defer delete(seen, value)
		switch value := value.(type) {
		case *ssa.Call:
			return calledAPI(&value.Call)
		case *ssa.Extract:
			if value.Index == 0 {
				return resolve(value.Tuple, depth+1)
			}
		case *ssa.MakeInterface:
			return resolve(value.X, depth+1)
		case *ssa.ChangeInterface:
			return resolve(value.X, depth+1)
		case *ssa.ChangeType:
			return resolve(value.X, depth+1)
		case *ssa.Phi:
			var common apiIdentity
			for index, edge := range value.Edges {
				next := resolve(edge, depth+1)
				if next == (apiIdentity{}) || index > 0 && next != common {
					return apiIdentity{}
				}
				common = next
			}
			return common
		}
		return apiIdentity{}
	}
	return resolve(value, 0)
}

func (v *values) resolve(value ssa.Value, seen map[ssa.Value]bool, depth int) constant.Value {
	if value == nil || depth > 16 || seen[value] {
		return nil
	}
	seen[value] = true
	defer delete(seen, value)
	resolve := func(child ssa.Value) constant.Value { return v.resolve(child, seen, depth+1) }
	switch value := value.(type) {
	case *ssa.Const:
		if value.Value != nil && value.Value.Kind() == constant.Int {
			return value.Value
		}
	case *ssa.Convert:
		number := resolve(value.X)
		if integerFits(number, value.Type()) {
			return number
		}
	case *ssa.ChangeType:
		return resolve(value.X)
	case *ssa.Phi:
		var result constant.Value
		for _, edge := range value.Edges {
			next := resolve(edge)
			if next == nil || result != nil && !constant.Compare(result, token.EQL, next) {
				return nil
			}
			result = next
		}
		return result
	case *ssa.BinOp:
		a, b := resolve(value.X), resolve(value.Y)
		if a == nil || b == nil {
			return nil
		}
		switch value.Op {
		case token.ADD, token.SUB, token.MUL, token.AND, token.OR, token.XOR:
			number := constant.BinaryOp(a, value.Op, b)
			if integerFits(number, value.Type()) {
				return number
			}
		}
	case *ssa.Parameter:
		function := value.Parent()
		if v.escaped[function] || function.Signature.Recv() != nil || function.Parent() != nil ||
			function.Object() == nil || function.Object().Exported() {
			return nil
		}
		index := -1
		for i, parameter := range function.Params {
			if parameter == value {
				index = i
			}
		}
		var result constant.Value
		for _, call := range v.callers[function] {
			if index < 0 || index >= len(call.Args) {
				return nil
			}
			next := resolve(call.Args[index])
			if next == nil || result != nil && !constant.Compare(result, token.EQL, next) {
				return nil
			}
			result = next
		}
		return result
	}
	return nil
}

func integerFits(number constant.Value, target types.Type) bool {
	if number == nil {
		return false
	}
	value, ok := constant.Int64Val(number)
	if !ok {
		return false
	}
	basic, ok := target.Underlying().(*types.Basic)
	if !ok {
		return false
	}
	switch basic.Kind() {
	case types.Int8:
		return value >= -128 && value <= 127
	case types.Uint8:
		return value >= 0 && value <= 255
	case types.Int16:
		return value >= -32768 && value <= 32767
	case types.Uint16:
		return value >= 0 && value <= 65535
	case types.Int32, types.Int:
		return value >= -1<<31 && value < 1<<31
	case types.Uint32, types.Uint:
		return value >= 0 && value < 1<<32
	case types.Int64, types.UntypedInt:
		return true
	case types.Uint64, types.Uintptr:
		return value >= 0
	}
	return false
}

func (v *values) length(value ssa.Value) (int64, bool) {
	switch value := value.(type) {
	case *ssa.MakeSlice:
		return v.integer(value.Len)
	case *ssa.Convert:
		if source, ok := value.X.(*ssa.Const); ok && source.Value != nil && source.Value.Kind() == constant.String {
			return int64(len(constant.StringVal(source.Value))), true
		}
	case *ssa.Slice:
		pointer, ok := value.X.Type().Underlying().(*types.Pointer)
		if !ok {
			return 0, false
		}
		array, ok := pointer.Elem().Underlying().(*types.Array)
		if !ok {
			return 0, false
		}
		low, high := int64(0), array.Len()
		if value.Low != nil {
			var known bool
			low, known = v.integer(value.Low)
			if !known {
				return 0, false
			}
		}
		if value.High != nil {
			var known bool
			high, known = v.integer(value.High)
			if !known {
				return 0, false
			}
		}
		return high - low, high >= low && high <= array.Len() && low >= 0
	}
	return 0, false
}
