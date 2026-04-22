// Package interpol compiles interpolated strings into CEL programs.
package interpol

import (
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common"
	"github.com/google/cel-go/common/operators"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"

	"github.com/antlr4-go/antlr/v4"
	"github.com/google/cel-go/common/ast"
	"github.com/google/cel-go/parser/gen"

	exprpb "google.golang.org/genproto/googleapis/api/expr/v1alpha1"
)

// Compile compiles a string containing interpolated ${...} CEL expressions.
// It returns (nil, nil) if the string doesn't contain any expressions.
//
//	// a string like
//	`hello ${2 + 2} world`
//
//	// becomes a CEL expression like
//	`"hello " + interpol(string(2+2)) + " world"`
//
// The default interpol function returns its argument.
// To transform or validate the result of interpolation,
// add your own interpol function to the given CEL env.
func Compile(env *cel.Env, s string) (cel.Program, error) {
	if !strings.Contains(s, "${") {
		return nil, nil
	}
	if env == nil {
		return nil, errors.New("nil env")
	}

	env, err := env.Extend(cel.ClearMacros())
	if err != nil {
		return nil, err
	}

	if !env.HasFunction("interpol") {
		env, err = env.Extend(cel.Function("interpol",
			cel.Overload("interpol", []*cel.Type{cel.StringType}, cel.StringType,
				cel.UnaryBinding(func(arg ref.Val) ref.Val {
					return arg
				}),
			),
		))

		if err != nil {
			return nil, err
		}
	}

	ast, err := compile(env, s)
	if err != nil {
		return nil, err
	}

	return env.Program(ast)
}

type seg struct {
	start int
	end   int

	bodyStart int
	bodyEnd   int
}

func (s seg) lit() bool {
	return s.bodyStart == 0 && s.bodyEnd == 0
}

func (seg seg) text(s string) string {
	return s[seg.start:seg.end]
}

func (s seg) rng() ast.OffsetRange {
	return ast.OffsetRange{
		Start: int32(s.start),
		Stop:  int32(s.end),
	}
}

type part struct {
	expr ast.Expr
	span ast.OffsetRange
}

func compile(env *cel.Env, s string) (*cel.Ast, error) {
	src := common.NewTextSource(s)
	segs, err := scan(src, s)
	if err != nil {
		return nil, err
	}

	fac := ast.NewExprFactory()
	info := ast.NewSourceInfo(src)
	nextID := int64(1)
	newID := func(span ast.OffsetRange) int64 {
		id := nextID
		nextID++
		info.SetOffsetRange(id, span)
		return id
	}

	parts := make([]part, 0, len(segs))
	for _, seg := range segs {
		if seg.lit() {
			id := newID(seg.rng())
			parts = append(parts, part{
				expr: fac.NewLiteral(id, types.String(seg.text(s))),
				span: seg.rng(),
			})

			continue
		}

		rel := &relativeSource{
			Source:     src,
			local:      common.NewTextSource(s[seg.bodyStart:seg.bodyEnd]),
			baseOffset: int32(seg.bodyStart),
		}

		parsed, issues := env.ParseSource(rel)
		if err := issues.Err(); err != nil {
			return nil, err
		}

		child := merge(fac, info, parsed.NativeRep(), &nextID)
		wrapSpan := seg.rng()

		parts = append(parts, part{
			span: wrapSpan,
			expr: fac.NewCall(newID(wrapSpan), "interpol",
				fac.NewCall(newID(wrapSpan), "string", child),
			),
		})
	}

	if len(parts) == 0 {
		return nil, errors.New("no parts")
	}

	root := parts[0].expr
	rootSpan := parts[0].span
	for _, part := range parts[1:] {
		rootSpan = ast.OffsetRange{
			Start: rootSpan.Start,
			Stop:  part.span.Stop,
		}

		root = fac.NewCall(newID(rootSpan), operators.Add, root, part.expr)
	}

	expr, err := ast.ExprToProto(root)
	if err != nil {
		return nil, err
	}

	sourceInfo, err := ast.SourceInfoToProto(info)
	if err != nil {
		return nil, err
	}

	parsed := cel.ParsedExprToAstWithSource(&exprpb.ParsedExpr{
		Expr:       expr,
		SourceInfo: sourceInfo,
	}, src)

	checked, issues := env.Check(parsed)
	if err := issues.Err(); err != nil {
		return nil, err
	}

	if checked.OutputType() != cel.StringType {
		return nil, fmt.Errorf("expr is %s, not string", cel.FormatCELType(checked.OutputType()))
	}

	return checked, nil
}

func merge(fac ast.ExprFactory, dst *ast.SourceInfo, parsed *ast.AST, nextID *int64) ast.Expr {
	ids := map[int64]int64{}
	genid := func(old int64) int64 {
		if id, ok := ids[old]; ok {
			return id
		}

		id := *nextID
		*nextID = id + 1
		ids[old] = id
		return id
	}

	expr := fac.CopyExpr(parsed.Expr())
	expr.RenumberIDs(genid)

	for old, off := range parsed.SourceInfo().OffsetRanges() {
		dst.SetOffsetRange(genid(old), off)
	}

	return expr
}

func scan(src common.Source, s string) ([]seg, error) {
	var segments []seg
	cursor := 0

	for {
		idx := strings.Index(s[cursor:], "${")
		if idx < 0 {
			if cursor < len(s) {
				segments = append(segments, seg{
					start: cursor,
					end:   len(s),
				})
			}
			return segments, nil
		}

		start := cursor + idx
		if start > cursor {
			segments = append(segments, seg{
				start: cursor,
				end:   start,
			})
		}

		bodyEnd, err := scanExpr(src, s, start)
		if err != nil {
			return nil, err
		}
		segments = append(segments, seg{
			start:     start,
			end:       bodyEnd + 1,
			bodyStart: start + 2,
			bodyEnd:   bodyEnd,
		})
		cursor = bodyEnd + 1
	}
}

func scanExpr(src common.Source, s string, interpStart int) (int, error) {
	bodyStart := interpStart + 2
	remaining := s[bodyStart:]
	runeOffsets := runeByteOffsets(remaining)
	lexer := gen.NewCELLexer(antlr.NewInputStream(remaining))

	depth := 0
	for {
		tok := lexer.NextToken()
		if tok.GetTokenType() == antlr.TokenEOF {
			return 0, serr(src, int32(interpStart), "unterminated interpolation")
		}
		if tok.GetChannel() != antlr.TokenDefaultChannel {
			continue
		}

		switch tok.GetTokenType() {
		case gen.CELLexerLBRACE:
			depth++

		case gen.CELLexerRBRACE:
			if depth == 0 {
				return bodyStart + runeOffsets[tok.GetStart()], nil
			}
			depth--
		}
	}
}

func runeByteOffsets(s string) []int {
	offsets := make([]int, 0, utf8.RuneCountInString(s)+1)
	for i := range s {
		offsets = append(offsets, i)
	}
	offsets = append(offsets, len(s))
	return offsets
}

func serr(src common.Source, offset int32, format string, args ...any) error {
	errs := common.NewErrors(src)
	loc, found := src.OffsetLocation(offset)
	if !found {
		loc = common.NoLocation
	}
	errs.ReportError(loc, format, args...)
	return cel.NewIssues(errs).Err()
}

type relativeSource struct {
	common.Source
	local common.Source

	baseOffset int32
}

func (src *relativeSource) Content() string {
	return src.local.Content()
}

func (src *relativeSource) OffsetLocation(offset int32) (common.Location, bool) {
	return src.Source.OffsetLocation(src.baseOffset + offset)
}
