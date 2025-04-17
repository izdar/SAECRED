
module MenhirBasics = struct
  
  exception Error
  
  let _eRR =
    fun _s ->
      raise Error
  
  type token = 
    | TYPEANNOT
    | TRUE
    | TIMES
    | STRING of (
# 55 "lib/parser.mly"
      (string)
# 18 "lib/parser.ml"
  )
    | STR
    | SEMICOLON
    | RPAREN
    | RCURLY
    | PRODUCTION
    | PLUS
    | OPTION
    | OF
    | MINUS
    | MACHINEINT
    | LXOR
    | LTE
    | LT
    | LPAREN
    | LOR
    | LNOT
    | LIMPLIES
    | LENGTH
    | LCURLY
    | LAND
    | INTTOBITVECTOR
    | INTEGER of (
# 52 "lib/parser.mly"
      (int)
# 44 "lib/parser.ml"
  )
    | INT
    | ID of (
# 54 "lib/parser.mly"
      (string)
# 50 "lib/parser.ml"
  )
    | GTE
    | GT
    | FALSE
    | EQ
    | EOF
    | DOT
    | DIV
    | COMMA
    | CASE
    | BVXOR
    | BVOR
    | BVNOT
    | BVLTE
    | BVLT
    | BVGTE
    | BVGT
    | BVAND
    | BOOL
    | BITVECTOR
    | BITS of (
# 53 "lib/parser.mly"
      (bool list)
# 74 "lib/parser.ml"
  )
    | BITLIST
    | ASSIGN
    | ARROW
  
end

include MenhirBasics

# 1 "lib/parser.mly"
  
open Ast

# 88 "lib/parser.ml"

type ('s, 'r) _menhir_state = 
  | MenhirState000 : ('s, _menhir_box_s) _menhir_state
    (** State 000.
        Stack shape : .
        Start symbol: s. *)

  | MenhirState019 : (('s, _menhir_box_s) _menhir_cell1_nonterminal _menhir_cell0_il_type, _menhir_box_s) _menhir_state
    (** State 019.
        Stack shape : nonterminal il_type.
        Start symbol: s. *)

  | MenhirState020 : (('s, _menhir_box_s) _menhir_cell1_LCURLY, _menhir_box_s) _menhir_state
    (** State 020.
        Stack shape : LCURLY.
        Start symbol: s. *)

  | MenhirState023 : (('s, _menhir_box_s) _menhir_cell1_PLUS, _menhir_box_s) _menhir_state
    (** State 023.
        Stack shape : PLUS.
        Start symbol: s. *)

  | MenhirState024 : (('s, _menhir_box_s) _menhir_cell1_MINUS, _menhir_box_s) _menhir_state
    (** State 024.
        Stack shape : MINUS.
        Start symbol: s. *)

  | MenhirState025 : (('s, _menhir_box_s) _menhir_cell1_LPAREN, _menhir_box_s) _menhir_state
    (** State 025.
        Stack shape : LPAREN.
        Start symbol: s. *)

  | MenhirState026 : (('s, _menhir_box_s) _menhir_cell1_LNOT, _menhir_box_s) _menhir_state
    (** State 026.
        Stack shape : LNOT.
        Start symbol: s. *)

  | MenhirState028 : (('s, _menhir_box_s) _menhir_cell1_LENGTH, _menhir_box_s) _menhir_state
    (** State 028.
        Stack shape : LENGTH.
        Start symbol: s. *)

  | MenhirState032 : (('s, _menhir_box_s) _menhir_cell1_INTTOBITVECTOR _menhir_cell0_INTEGER, _menhir_box_s) _menhir_state
    (** State 032.
        Stack shape : INTTOBITVECTOR INTEGER.
        Start symbol: s. *)

  | MenhirState035 : (('s, _menhir_box_s) _menhir_cell1_CASE, _menhir_box_s) _menhir_state
    (** State 035.
        Stack shape : CASE.
        Start symbol: s. *)

  | MenhirState037 : ((('s, _menhir_box_s) _menhir_cell1_CASE, _menhir_box_s) _menhir_cell1_nt_expr, _menhir_box_s) _menhir_state
    (** State 037.
        Stack shape : CASE nt_expr.
        Start symbol: s. *)

  | MenhirState038 : (('s, _menhir_box_s) _menhir_cell1_OPTION, _menhir_box_s) _menhir_state
    (** State 038.
        Stack shape : OPTION.
        Start symbol: s. *)

  | MenhirState040 : ((('s, _menhir_box_s) _menhir_cell1_OPTION, _menhir_box_s) _menhir_cell1_nt_expr, _menhir_box_s) _menhir_state
    (** State 040.
        Stack shape : OPTION nt_expr.
        Start symbol: s. *)

  | MenhirState041 : (('s, _menhir_box_s) _menhir_cell1_BVNOT, _menhir_box_s) _menhir_state
    (** State 041.
        Stack shape : BVNOT.
        Start symbol: s. *)

  | MenhirState050 : (('s, _menhir_box_s) _menhir_cell1_nonterminal, _menhir_box_s) _menhir_state
    (** State 050.
        Stack shape : nonterminal.
        Start symbol: s. *)

  | MenhirState053 : (((('s, _menhir_box_s) _menhir_cell1_OPTION, _menhir_box_s) _menhir_cell1_nt_expr, _menhir_box_s) _menhir_cell1_expr, _menhir_box_s) _menhir_state
    (** State 053.
        Stack shape : OPTION nt_expr expr.
        Start symbol: s. *)

  | MenhirState054 : ((('s, _menhir_box_s) _menhir_cell1_expr, _menhir_box_s) _menhir_cell1_TIMES, _menhir_box_s) _menhir_state
    (** State 054.
        Stack shape : expr TIMES.
        Start symbol: s. *)

  | MenhirState056 : ((('s, _menhir_box_s) _menhir_cell1_expr, _menhir_box_s) _menhir_cell1_PLUS, _menhir_box_s) _menhir_state
    (** State 056.
        Stack shape : expr PLUS.
        Start symbol: s. *)

  | MenhirState057 : (((('s, _menhir_box_s) _menhir_cell1_expr, _menhir_box_s) _menhir_cell1_PLUS, _menhir_box_s) _menhir_cell1_expr, _menhir_box_s) _menhir_state
    (** State 057.
        Stack shape : expr PLUS expr.
        Start symbol: s. *)

  | MenhirState058 : ((('s, _menhir_box_s) _menhir_cell1_expr, _menhir_box_s) _menhir_cell1_DIV, _menhir_box_s) _menhir_state
    (** State 058.
        Stack shape : expr DIV.
        Start symbol: s. *)

  | MenhirState060 : ((('s, _menhir_box_s) _menhir_cell1_expr, _menhir_box_s) _menhir_cell1_MINUS, _menhir_box_s) _menhir_state
    (** State 060.
        Stack shape : expr MINUS.
        Start symbol: s. *)

  | MenhirState061 : (((('s, _menhir_box_s) _menhir_cell1_expr, _menhir_box_s) _menhir_cell1_MINUS, _menhir_box_s) _menhir_cell1_expr, _menhir_box_s) _menhir_state
    (** State 061.
        Stack shape : expr MINUS expr.
        Start symbol: s. *)

  | MenhirState062 : ((('s, _menhir_box_s) _menhir_cell1_expr, _menhir_box_s) _menhir_cell1_LXOR, _menhir_box_s) _menhir_state
    (** State 062.
        Stack shape : expr LXOR.
        Start symbol: s. *)

  | MenhirState063 : (((('s, _menhir_box_s) _menhir_cell1_expr, _menhir_box_s) _menhir_cell1_LXOR, _menhir_box_s) _menhir_cell1_expr, _menhir_box_s) _menhir_state
    (** State 063.
        Stack shape : expr LXOR expr.
        Start symbol: s. *)

  | MenhirState064 : ((('s, _menhir_box_s) _menhir_cell1_expr, _menhir_box_s) _menhir_cell1_LTE, _menhir_box_s) _menhir_state
    (** State 064.
        Stack shape : expr LTE.
        Start symbol: s. *)

  | MenhirState065 : (((('s, _menhir_box_s) _menhir_cell1_expr, _menhir_box_s) _menhir_cell1_LTE, _menhir_box_s) _menhir_cell1_expr, _menhir_box_s) _menhir_state
    (** State 065.
        Stack shape : expr LTE expr.
        Start symbol: s. *)

  | MenhirState066 : ((('s, _menhir_box_s) _menhir_cell1_expr, _menhir_box_s) _menhir_cell1_LT, _menhir_box_s) _menhir_state
    (** State 066.
        Stack shape : expr LT.
        Start symbol: s. *)

  | MenhirState067 : (((('s, _menhir_box_s) _menhir_cell1_expr, _menhir_box_s) _menhir_cell1_LT, _menhir_box_s) _menhir_cell1_expr, _menhir_box_s) _menhir_state
    (** State 067.
        Stack shape : expr LT expr.
        Start symbol: s. *)

  | MenhirState068 : ((('s, _menhir_box_s) _menhir_cell1_expr, _menhir_box_s) _menhir_cell1_LAND, _menhir_box_s) _menhir_state
    (** State 068.
        Stack shape : expr LAND.
        Start symbol: s. *)

  | MenhirState069 : (((('s, _menhir_box_s) _menhir_cell1_expr, _menhir_box_s) _menhir_cell1_LAND, _menhir_box_s) _menhir_cell1_expr, _menhir_box_s) _menhir_state
    (** State 069.
        Stack shape : expr LAND expr.
        Start symbol: s. *)

  | MenhirState070 : ((('s, _menhir_box_s) _menhir_cell1_expr, _menhir_box_s) _menhir_cell1_GTE, _menhir_box_s) _menhir_state
    (** State 070.
        Stack shape : expr GTE.
        Start symbol: s. *)

  | MenhirState071 : (((('s, _menhir_box_s) _menhir_cell1_expr, _menhir_box_s) _menhir_cell1_GTE, _menhir_box_s) _menhir_cell1_expr, _menhir_box_s) _menhir_state
    (** State 071.
        Stack shape : expr GTE expr.
        Start symbol: s. *)

  | MenhirState072 : ((('s, _menhir_box_s) _menhir_cell1_expr, _menhir_box_s) _menhir_cell1_GT, _menhir_box_s) _menhir_state
    (** State 072.
        Stack shape : expr GT.
        Start symbol: s. *)

  | MenhirState073 : (((('s, _menhir_box_s) _menhir_cell1_expr, _menhir_box_s) _menhir_cell1_GT, _menhir_box_s) _menhir_cell1_expr, _menhir_box_s) _menhir_state
    (** State 073.
        Stack shape : expr GT expr.
        Start symbol: s. *)

  | MenhirState074 : ((('s, _menhir_box_s) _menhir_cell1_expr, _menhir_box_s) _menhir_cell1_EQ, _menhir_box_s) _menhir_state
    (** State 074.
        Stack shape : expr EQ.
        Start symbol: s. *)

  | MenhirState075 : (((('s, _menhir_box_s) _menhir_cell1_expr, _menhir_box_s) _menhir_cell1_EQ, _menhir_box_s) _menhir_cell1_expr, _menhir_box_s) _menhir_state
    (** State 075.
        Stack shape : expr EQ expr.
        Start symbol: s. *)

  | MenhirState076 : ((('s, _menhir_box_s) _menhir_cell1_expr, _menhir_box_s) _menhir_cell1_BVLTE, _menhir_box_s) _menhir_state
    (** State 076.
        Stack shape : expr BVLTE.
        Start symbol: s. *)

  | MenhirState077 : (((('s, _menhir_box_s) _menhir_cell1_expr, _menhir_box_s) _menhir_cell1_BVLTE, _menhir_box_s) _menhir_cell1_expr, _menhir_box_s) _menhir_state
    (** State 077.
        Stack shape : expr BVLTE expr.
        Start symbol: s. *)

  | MenhirState078 : ((('s, _menhir_box_s) _menhir_cell1_expr, _menhir_box_s) _menhir_cell1_BVLT, _menhir_box_s) _menhir_state
    (** State 078.
        Stack shape : expr BVLT.
        Start symbol: s. *)

  | MenhirState079 : (((('s, _menhir_box_s) _menhir_cell1_expr, _menhir_box_s) _menhir_cell1_BVLT, _menhir_box_s) _menhir_cell1_expr, _menhir_box_s) _menhir_state
    (** State 079.
        Stack shape : expr BVLT expr.
        Start symbol: s. *)

  | MenhirState080 : ((('s, _menhir_box_s) _menhir_cell1_expr, _menhir_box_s) _menhir_cell1_BVGTE, _menhir_box_s) _menhir_state
    (** State 080.
        Stack shape : expr BVGTE.
        Start symbol: s. *)

  | MenhirState081 : (((('s, _menhir_box_s) _menhir_cell1_expr, _menhir_box_s) _menhir_cell1_BVGTE, _menhir_box_s) _menhir_cell1_expr, _menhir_box_s) _menhir_state
    (** State 081.
        Stack shape : expr BVGTE expr.
        Start symbol: s. *)

  | MenhirState082 : ((('s, _menhir_box_s) _menhir_cell1_expr, _menhir_box_s) _menhir_cell1_BVGT, _menhir_box_s) _menhir_state
    (** State 082.
        Stack shape : expr BVGT.
        Start symbol: s. *)

  | MenhirState083 : (((('s, _menhir_box_s) _menhir_cell1_expr, _menhir_box_s) _menhir_cell1_BVGT, _menhir_box_s) _menhir_cell1_expr, _menhir_box_s) _menhir_state
    (** State 083.
        Stack shape : expr BVGT expr.
        Start symbol: s. *)

  | MenhirState084 : ((('s, _menhir_box_s) _menhir_cell1_expr, _menhir_box_s) _menhir_cell1_BVAND, _menhir_box_s) _menhir_state
    (** State 084.
        Stack shape : expr BVAND.
        Start symbol: s. *)

  | MenhirState085 : (((('s, _menhir_box_s) _menhir_cell1_expr, _menhir_box_s) _menhir_cell1_BVAND, _menhir_box_s) _menhir_cell1_expr, _menhir_box_s) _menhir_state
    (** State 085.
        Stack shape : expr BVAND expr.
        Start symbol: s. *)

  | MenhirState086 : ((('s, _menhir_box_s) _menhir_cell1_expr, _menhir_box_s) _menhir_cell1_LOR, _menhir_box_s) _menhir_state
    (** State 086.
        Stack shape : expr LOR.
        Start symbol: s. *)

  | MenhirState087 : (((('s, _menhir_box_s) _menhir_cell1_expr, _menhir_box_s) _menhir_cell1_LOR, _menhir_box_s) _menhir_cell1_expr, _menhir_box_s) _menhir_state
    (** State 087.
        Stack shape : expr LOR expr.
        Start symbol: s. *)

  | MenhirState088 : ((('s, _menhir_box_s) _menhir_cell1_expr, _menhir_box_s) _menhir_cell1_LIMPLIES, _menhir_box_s) _menhir_state
    (** State 088.
        Stack shape : expr LIMPLIES.
        Start symbol: s. *)

  | MenhirState089 : (((('s, _menhir_box_s) _menhir_cell1_expr, _menhir_box_s) _menhir_cell1_LIMPLIES, _menhir_box_s) _menhir_cell1_expr, _menhir_box_s) _menhir_state
    (** State 089.
        Stack shape : expr LIMPLIES expr.
        Start symbol: s. *)

  | MenhirState090 : ((('s, _menhir_box_s) _menhir_cell1_expr, _menhir_box_s) _menhir_cell1_BVXOR, _menhir_box_s) _menhir_state
    (** State 090.
        Stack shape : expr BVXOR.
        Start symbol: s. *)

  | MenhirState091 : (((('s, _menhir_box_s) _menhir_cell1_expr, _menhir_box_s) _menhir_cell1_BVXOR, _menhir_box_s) _menhir_cell1_expr, _menhir_box_s) _menhir_state
    (** State 091.
        Stack shape : expr BVXOR expr.
        Start symbol: s. *)

  | MenhirState092 : ((('s, _menhir_box_s) _menhir_cell1_expr, _menhir_box_s) _menhir_cell1_BVOR, _menhir_box_s) _menhir_state
    (** State 092.
        Stack shape : expr BVOR.
        Start symbol: s. *)

  | MenhirState093 : (((('s, _menhir_box_s) _menhir_cell1_expr, _menhir_box_s) _menhir_cell1_BVOR, _menhir_box_s) _menhir_cell1_expr, _menhir_box_s) _menhir_state
    (** State 093.
        Stack shape : expr BVOR expr.
        Start symbol: s. *)

  | MenhirState096 : ((('s, _menhir_box_s) _menhir_cell1_INTTOBITVECTOR _menhir_cell0_INTEGER, _menhir_box_s) _menhir_cell1_expr, _menhir_box_s) _menhir_state
    (** State 096.
        Stack shape : INTTOBITVECTOR INTEGER expr.
        Start symbol: s. *)

  | MenhirState098 : ((('s, _menhir_box_s) _menhir_cell1_LENGTH, _menhir_box_s) _menhir_cell1_expr, _menhir_box_s) _menhir_state
    (** State 098.
        Stack shape : LENGTH expr.
        Start symbol: s. *)

  | MenhirState104 : ((('s, _menhir_box_s) _menhir_cell1_LPAREN, _menhir_box_s) _menhir_cell1_expr, _menhir_box_s) _menhir_state
    (** State 104.
        Stack shape : LPAREN expr.
        Start symbol: s. *)

  | MenhirState106 : ((('s, _menhir_box_s) _menhir_cell1_MINUS, _menhir_box_s) _menhir_cell1_expr, _menhir_box_s) _menhir_state
    (** State 106.
        Stack shape : MINUS expr.
        Start symbol: s. *)

  | MenhirState107 : ((('s, _menhir_box_s) _menhir_cell1_PLUS, _menhir_box_s) _menhir_cell1_expr, _menhir_box_s) _menhir_state
    (** State 107.
        Stack shape : PLUS expr.
        Start symbol: s. *)

  | MenhirState111 : (('s, _menhir_box_s) _menhir_cell1_semantic_constraint, _menhir_box_s) _menhir_state
    (** State 111.
        Stack shape : semantic_constraint.
        Start symbol: s. *)

  | MenhirState114 : (('s, _menhir_box_s) _menhir_cell1_nonterminal, _menhir_box_s) _menhir_state
    (** State 114.
        Stack shape : nonterminal.
        Start symbol: s. *)

  | MenhirState115 : ((('s, _menhir_box_s) _menhir_cell1_nonterminal, _menhir_box_s) _menhir_cell1_expr, _menhir_box_s) _menhir_state
    (** State 115.
        Stack shape : nonterminal expr.
        Start symbol: s. *)

  | MenhirState116 : (('s, _menhir_box_s) _menhir_cell1_expr, _menhir_box_s) _menhir_state
    (** State 116.
        Stack shape : expr.
        Start symbol: s. *)

  | MenhirState120 : (('s, _menhir_box_s) _menhir_cell1_nonterminal, _menhir_box_s) _menhir_state
    (** State 120.
        Stack shape : nonterminal.
        Start symbol: s. *)

  | MenhirState122 : (('s, _menhir_box_s) _menhir_cell1_ID, _menhir_box_s) _menhir_state
    (** State 122.
        Stack shape : ID.
        Start symbol: s. *)

  | MenhirState127 : (('s, _menhir_box_s) _menhir_cell1_rhs, _menhir_box_s) _menhir_state
    (** State 127.
        Stack shape : rhs.
        Start symbol: s. *)

  | MenhirState130 : (('s, _menhir_box_s) _menhir_cell1_nonempty_list_grammar_element_, _menhir_box_s) _menhir_state
    (** State 130.
        Stack shape : nonempty_list(grammar_element).
        Start symbol: s. *)

  | MenhirState132 : (('s, _menhir_box_s) _menhir_cell1_grammar_element, _menhir_box_s) _menhir_state
    (** State 132.
        Stack shape : grammar_element.
        Start symbol: s. *)

  | MenhirState136 : (('s, _menhir_box_s) _menhir_cell1_element, _menhir_box_s) _menhir_state
    (** State 136.
        Stack shape : element.
        Start symbol: s. *)


and ('s, 'r) _menhir_cell1_element = 
  | MenhirCell1_element of 's * ('s, 'r) _menhir_state * (Ast.element)

and ('s, 'r) _menhir_cell1_expr = 
  | MenhirCell1_expr of 's * ('s, 'r) _menhir_state * (Ast.expr)

and ('s, 'r) _menhir_cell1_grammar_element = 
  | MenhirCell1_grammar_element of 's * ('s, 'r) _menhir_state * (Ast.grammar_element)

and 's _menhir_cell0_il_type = 
  | MenhirCell0_il_type of 's * (Ast.il_type)

and ('s, 'r) _menhir_cell1_nonempty_list_grammar_element_ = 
  | MenhirCell1_nonempty_list_grammar_element_ of 's * ('s, 'r) _menhir_state * (Ast.grammar_element list)

and ('s, 'r) _menhir_cell1_nonterminal = 
  | MenhirCell1_nonterminal of 's * ('s, 'r) _menhir_state * (string)

and ('s, 'r) _menhir_cell1_nt_expr = 
  | MenhirCell1_nt_expr of 's * ('s, 'r) _menhir_state * (Ast.nt_expr)

and ('s, 'r) _menhir_cell1_rhs = 
  | MenhirCell1_rhs of 's * ('s, 'r) _menhir_state * (Ast.prod_rule_rhs)

and ('s, 'r) _menhir_cell1_semantic_constraint = 
  | MenhirCell1_semantic_constraint of 's * ('s, 'r) _menhir_state * (Ast.semantic_constraint)

and ('s, 'r) _menhir_cell1_BVAND = 
  | MenhirCell1_BVAND of 's * ('s, 'r) _menhir_state

and ('s, 'r) _menhir_cell1_BVGT = 
  | MenhirCell1_BVGT of 's * ('s, 'r) _menhir_state

and ('s, 'r) _menhir_cell1_BVGTE = 
  | MenhirCell1_BVGTE of 's * ('s, 'r) _menhir_state

and ('s, 'r) _menhir_cell1_BVLT = 
  | MenhirCell1_BVLT of 's * ('s, 'r) _menhir_state

and ('s, 'r) _menhir_cell1_BVLTE = 
  | MenhirCell1_BVLTE of 's * ('s, 'r) _menhir_state

and ('s, 'r) _menhir_cell1_BVNOT = 
  | MenhirCell1_BVNOT of 's * ('s, 'r) _menhir_state

and ('s, 'r) _menhir_cell1_BVOR = 
  | MenhirCell1_BVOR of 's * ('s, 'r) _menhir_state

and ('s, 'r) _menhir_cell1_BVXOR = 
  | MenhirCell1_BVXOR of 's * ('s, 'r) _menhir_state

and ('s, 'r) _menhir_cell1_CASE = 
  | MenhirCell1_CASE of 's * ('s, 'r) _menhir_state

and ('s, 'r) _menhir_cell1_DIV = 
  | MenhirCell1_DIV of 's * ('s, 'r) _menhir_state

and ('s, 'r) _menhir_cell1_EQ = 
  | MenhirCell1_EQ of 's * ('s, 'r) _menhir_state

and ('s, 'r) _menhir_cell1_GT = 
  | MenhirCell1_GT of 's * ('s, 'r) _menhir_state

and ('s, 'r) _menhir_cell1_GTE = 
  | MenhirCell1_GTE of 's * ('s, 'r) _menhir_state

and ('s, 'r) _menhir_cell1_ID = 
  | MenhirCell1_ID of 's * ('s, 'r) _menhir_state * (
# 54 "lib/parser.mly"
      (string)
# 507 "lib/parser.ml"
)

and 's _menhir_cell0_INTEGER = 
  | MenhirCell0_INTEGER of 's * (
# 52 "lib/parser.mly"
      (int)
# 514 "lib/parser.ml"
)

and ('s, 'r) _menhir_cell1_INTTOBITVECTOR = 
  | MenhirCell1_INTTOBITVECTOR of 's * ('s, 'r) _menhir_state

and ('s, 'r) _menhir_cell1_LAND = 
  | MenhirCell1_LAND of 's * ('s, 'r) _menhir_state

and ('s, 'r) _menhir_cell1_LCURLY = 
  | MenhirCell1_LCURLY of 's * ('s, 'r) _menhir_state

and ('s, 'r) _menhir_cell1_LENGTH = 
  | MenhirCell1_LENGTH of 's * ('s, 'r) _menhir_state

and ('s, 'r) _menhir_cell1_LIMPLIES = 
  | MenhirCell1_LIMPLIES of 's * ('s, 'r) _menhir_state

and ('s, 'r) _menhir_cell1_LNOT = 
  | MenhirCell1_LNOT of 's * ('s, 'r) _menhir_state

and ('s, 'r) _menhir_cell1_LOR = 
  | MenhirCell1_LOR of 's * ('s, 'r) _menhir_state

and ('s, 'r) _menhir_cell1_LPAREN = 
  | MenhirCell1_LPAREN of 's * ('s, 'r) _menhir_state

and ('s, 'r) _menhir_cell1_LT = 
  | MenhirCell1_LT of 's * ('s, 'r) _menhir_state

and ('s, 'r) _menhir_cell1_LTE = 
  | MenhirCell1_LTE of 's * ('s, 'r) _menhir_state

and ('s, 'r) _menhir_cell1_LXOR = 
  | MenhirCell1_LXOR of 's * ('s, 'r) _menhir_state

and ('s, 'r) _menhir_cell1_MINUS = 
  | MenhirCell1_MINUS of 's * ('s, 'r) _menhir_state

and ('s, 'r) _menhir_cell1_OPTION = 
  | MenhirCell1_OPTION of 's * ('s, 'r) _menhir_state

and ('s, 'r) _menhir_cell1_PLUS = 
  | MenhirCell1_PLUS of 's * ('s, 'r) _menhir_state

and ('s, 'r) _menhir_cell1_TIMES = 
  | MenhirCell1_TIMES of 's * ('s, 'r) _menhir_state

and _menhir_box_s = 
  | MenhirBox_s of (Ast.ast) [@@unboxed]

let _menhir_action_01 =
  fun e1 e2 ->
    (
# 170 "lib/parser.mly"
                                          ( [(e1, e2)] )
# 570 "lib/parser.ml"
     : (Ast.case list))

let _menhir_action_02 =
  fun cs e1 e2 ->
    (
# 171 "lib/parser.mly"
                                                         ( (e1, e2) :: cs )
# 578 "lib/parser.ml"
     : (Ast.case list))

let _menhir_action_03 =
  fun nt scs t ->
    (
# 83 "lib/parser.mly"
  ( 
    match scs with 
    | None -> TypeAnnotation (nt, t, []) 
    | Some scs -> TypeAnnotation (nt, t, scs) 
  )
# 590 "lib/parser.ml"
     : (Ast.element))

let _menhir_action_04 =
  fun nt rhss ->
    (
# 90 "lib/parser.mly"
  ( ProdRule (nt, rhss) )
# 598 "lib/parser.ml"
     : (Ast.element))

let _menhir_action_05 =
  fun e1 e2 ->
    (
# 125 "lib/parser.mly"
                             ( BinOp (e1, LAnd, e2) )
# 606 "lib/parser.ml"
     : (Ast.expr))

let _menhir_action_06 =
  fun e1 e2 ->
    (
# 126 "lib/parser.mly"
                            ( BinOp (e1, LOr, e2) )
# 614 "lib/parser.ml"
     : (Ast.expr))

let _menhir_action_07 =
  fun e1 e2 ->
    (
# 127 "lib/parser.mly"
                             ( BinOp (e1, LXor, e2) )
# 622 "lib/parser.ml"
     : (Ast.expr))

let _menhir_action_08 =
  fun e1 e2 ->
    (
# 128 "lib/parser.mly"
                                 ( BinOp (e1, LImplies, e2) )
# 630 "lib/parser.ml"
     : (Ast.expr))

let _menhir_action_09 =
  fun e1 e2 ->
    (
# 129 "lib/parser.mly"
                             ( BinOp (e1, Plus, e2) )
# 638 "lib/parser.ml"
     : (Ast.expr))

let _menhir_action_10 =
  fun e1 e2 ->
    (
# 130 "lib/parser.mly"
                              ( BinOp (e1, Minus, e2) )
# 646 "lib/parser.ml"
     : (Ast.expr))

let _menhir_action_11 =
  fun e1 e2 ->
    (
# 131 "lib/parser.mly"
                              ( BinOp (e1, Times, e2) )
# 654 "lib/parser.ml"
     : (Ast.expr))

let _menhir_action_12 =
  fun e1 e2 ->
    (
# 132 "lib/parser.mly"
                            ( BinOp (e1, Div, e2) )
# 662 "lib/parser.ml"
     : (Ast.expr))

let _menhir_action_13 =
  fun e1 e2 ->
    (
# 133 "lib/parser.mly"
                              ( BinOp (e1, BVAnd, e2) )
# 670 "lib/parser.ml"
     : (Ast.expr))

let _menhir_action_14 =
  fun e1 e2 ->
    (
# 134 "lib/parser.mly"
                             ( BinOp (e1, BVOr, e2) )
# 678 "lib/parser.ml"
     : (Ast.expr))

let _menhir_action_15 =
  fun e1 e2 ->
    (
# 135 "lib/parser.mly"
                              ( BinOp (e1, BVXor, e2) )
# 686 "lib/parser.ml"
     : (Ast.expr))

let _menhir_action_16 =
  fun e1 e2 ->
    (
# 137 "lib/parser.mly"
                           ( CompOp (e1, Lt, e2) )
# 694 "lib/parser.ml"
     : (Ast.expr))

let _menhir_action_17 =
  fun e1 e2 ->
    (
# 138 "lib/parser.mly"
                            ( CompOp (e1, Lte, e2) )
# 702 "lib/parser.ml"
     : (Ast.expr))

let _menhir_action_18 =
  fun e1 e2 ->
    (
# 139 "lib/parser.mly"
                           ( CompOp (e1, Gt, e2) )
# 710 "lib/parser.ml"
     : (Ast.expr))

let _menhir_action_19 =
  fun e1 e2 ->
    (
# 140 "lib/parser.mly"
                            ( CompOp (e1, Gte, e2) )
# 718 "lib/parser.ml"
     : (Ast.expr))

let _menhir_action_20 =
  fun e1 e2 ->
    (
# 141 "lib/parser.mly"
                           ( CompOp (e1, Eq, e2) )
# 726 "lib/parser.ml"
     : (Ast.expr))

let _menhir_action_21 =
  fun e1 e2 ->
    (
# 142 "lib/parser.mly"
                             ( CompOp (e1, BVLt, e2) )
# 734 "lib/parser.ml"
     : (Ast.expr))

let _menhir_action_22 =
  fun e1 e2 ->
    (
# 143 "lib/parser.mly"
                              ( CompOp (e1, BVLte, e2) )
# 742 "lib/parser.ml"
     : (Ast.expr))

let _menhir_action_23 =
  fun e1 e2 ->
    (
# 144 "lib/parser.mly"
                             ( CompOp (e1, BVGt, e2) )
# 750 "lib/parser.ml"
     : (Ast.expr))

let _menhir_action_24 =
  fun e1 e2 ->
    (
# 145 "lib/parser.mly"
                              ( CompOp (e1, BVGte, e2) )
# 758 "lib/parser.ml"
     : (Ast.expr))

let _menhir_action_25 =
  fun e ->
    (
# 147 "lib/parser.mly"
                  ( UnOp (BVNot, e) )
# 766 "lib/parser.ml"
     : (Ast.expr))

let _menhir_action_26 =
  fun e ->
    (
# 148 "lib/parser.mly"
                 ( UnOp (UPlus, e) )
# 774 "lib/parser.ml"
     : (Ast.expr))

let _menhir_action_27 =
  fun e ->
    (
# 149 "lib/parser.mly"
                  ( UnOp (UMinus, e) )
# 782 "lib/parser.ml"
     : (Ast.expr))

let _menhir_action_28 =
  fun e ->
    (
# 150 "lib/parser.mly"
                 ( UnOp (LNot, e) )
# 790 "lib/parser.ml"
     : (Ast.expr))

let _menhir_action_29 =
  fun i ->
    (
# 152 "lib/parser.mly"
               ( IntConst (i) )
# 798 "lib/parser.ml"
     : (Ast.expr))

let _menhir_action_30 =
  fun s ->
    (
# 153 "lib/parser.mly"
              ( StrConst (s) )
# 806 "lib/parser.ml"
     : (Ast.expr))

let _menhir_action_31 =
  fun () ->
    (
# 154 "lib/parser.mly"
        ( BConst (true) )
# 814 "lib/parser.ml"
     : (Ast.expr))

let _menhir_action_32 =
  fun () ->
    (
# 155 "lib/parser.mly"
         ( BConst (false) )
# 822 "lib/parser.ml"
     : (Ast.expr))

let _menhir_action_33 =
  fun bv ->
    (
# 156 "lib/parser.mly"
            ( BVConst (List.length bv, bv) )
# 830 "lib/parser.ml"
     : (Ast.expr))

let _menhir_action_34 =
  fun bl ->
    (
# 157 "lib/parser.mly"
                                      ( BLConst (bl) )
# 838 "lib/parser.ml"
     : (Ast.expr))

let _menhir_action_35 =
  fun e width ->
    (
# 160 "lib/parser.mly"
                                                    ( BVCast (width, e) )
# 846 "lib/parser.ml"
     : (Ast.expr))

let _menhir_action_36 =
  fun e ->
    (
# 161 "lib/parser.mly"
                                    ( Length (e) )
# 854 "lib/parser.ml"
     : (Ast.expr))

let _menhir_action_37 =
  fun cs e ->
    (
# 163 "lib/parser.mly"
                                        ( CaseExpr (e, cs) )
# 862 "lib/parser.ml"
     : (Ast.expr))

let _menhir_action_38 =
  fun e index ->
    (
# 165 "lib/parser.mly"
                                      ( NTExpr (e, index) )
# 870 "lib/parser.ml"
     : (Ast.expr))

let _menhir_action_39 =
  fun e ->
    (
# 167 "lib/parser.mly"
                            ( e )
# 878 "lib/parser.ml"
     : (Ast.expr))

let _menhir_action_40 =
  fun nt ->
    (
# 116 "lib/parser.mly"
                   ( Nonterminal(nt) )
# 886 "lib/parser.ml"
     : (Ast.grammar_element))

let _menhir_action_41 =
  fun i nt ->
    (
# 117 "lib/parser.mly"
                                ( NamedNonterminal (i, nt) )
# 894 "lib/parser.ml"
     : (Ast.grammar_element))

let _menhir_action_42 =
  fun () ->
    (
# 101 "lib/parser.mly"
       ( Bool )
# 902 "lib/parser.ml"
     : (Ast.il_type))

let _menhir_action_43 =
  fun () ->
    (
# 102 "lib/parser.mly"
      ( Int )
# 910 "lib/parser.ml"
     : (Ast.il_type))

let _menhir_action_44 =
  fun () ->
    (
# 103 "lib/parser.mly"
      ( String )
# 918 "lib/parser.ml"
     : (Ast.il_type))

let _menhir_action_45 =
  fun len ->
    (
# 104 "lib/parser.mly"
                                            ( BitVector (len) )
# 926 "lib/parser.ml"
     : (Ast.il_type))

let _menhir_action_46 =
  fun () ->
    (
# 105 "lib/parser.mly"
          ( BitList )
# 934 "lib/parser.ml"
     : (Ast.il_type))

let _menhir_action_47 =
  fun width ->
    (
# 106 "lib/parser.mly"
                                               ( MachineInt (width) )
# 942 "lib/parser.ml"
     : (Ast.il_type))

let _menhir_action_48 =
  fun index ->
    (
# 174 "lib/parser.mly"
                                   ( index )
# 950 "lib/parser.ml"
     : (int))

let _menhir_action_49 =
  fun () ->
    (
# 216 "<standard.mly>"
    ( [] )
# 958 "lib/parser.ml"
     : (Ast.ast))

let _menhir_action_50 =
  fun x xs ->
    (
# 219 "<standard.mly>"
    ( x :: xs )
# 966 "lib/parser.ml"
     : (Ast.ast))

let _menhir_action_51 =
  fun x ->
    (
# 228 "<standard.mly>"
    ( [ x ] )
# 974 "lib/parser.ml"
     : (Ast.grammar_element list))

let _menhir_action_52 =
  fun x xs ->
    (
# 231 "<standard.mly>"
    ( x :: xs )
# 982 "lib/parser.ml"
     : (Ast.grammar_element list))

let _menhir_action_53 =
  fun str ->
    (
# 181 "lib/parser.mly"
                    ( str )
# 990 "lib/parser.ml"
     : (string))

let _menhir_action_54 =
  fun nt ->
    (
# 177 "lib/parser.mly"
                   ( [nt] )
# 998 "lib/parser.ml"
     : (Ast.nt_expr))

let _menhir_action_55 =
  fun nt nts ->
    (
# 178 "lib/parser.mly"
                                        ( nt :: nts )
# 1006 "lib/parser.ml"
     : (Ast.nt_expr))

let _menhir_action_56 =
  fun () ->
    (
# 111 "<standard.mly>"
    ( None )
# 1014 "lib/parser.ml"
     : (int option))

let _menhir_action_57 =
  fun x ->
    (
# 114 "<standard.mly>"
    ( Some x )
# 1022 "lib/parser.ml"
     : (int option))

let _menhir_action_58 =
  fun () ->
    (
# 111 "<standard.mly>"
    ( None )
# 1030 "lib/parser.ml"
     : (Ast.semantic_constraint list option))

let _menhir_action_59 =
  fun x ->
    (
# 114 "<standard.mly>"
    ( Some x )
# 1038 "lib/parser.ml"
     : (Ast.semantic_constraint list option))

let _menhir_action_60 =
  fun ges scs ->
    (
# 94 "lib/parser.mly"
  ( 
    match scs with 
    | None -> Rhs (ges, [])
    | Some scs -> Rhs (ges, scs) 
  )
# 1050 "lib/parser.ml"
     : (Ast.prod_rule_rhs))

let _menhir_action_61 =
  fun d ->
    (
# 77 "lib/parser.mly"
                          ( d )
# 1058 "lib/parser.ml"
     : (Ast.ast))

let _menhir_action_62 =
  fun e nt ->
    (
# 120 "lib/parser.mly"
                                     ( Dependency (nt, e) )
# 1066 "lib/parser.ml"
     : (Ast.semantic_constraint))

let _menhir_action_63 =
  fun e ->
    (
# 121 "lib/parser.mly"
           ( SyGuSExpr e )
# 1074 "lib/parser.ml"
     : (Ast.semantic_constraint))

let _menhir_action_64 =
  fun sc ->
    (
# 112 "lib/parser.mly"
                                      ( [sc] )
# 1082 "lib/parser.ml"
     : (Ast.semantic_constraint list))

let _menhir_action_65 =
  fun sc scs ->
    (
# 113 "lib/parser.mly"
                                                                       ( sc :: scs )
# 1090 "lib/parser.ml"
     : (Ast.semantic_constraint list))

let _menhir_action_66 =
  fun scs ->
    (
# 109 "lib/parser.mly"
                                                  ( scs )
# 1098 "lib/parser.ml"
     : (Ast.semantic_constraint list))

let _menhir_action_67 =
  fun x ->
    (
# 250 "<standard.mly>"
    ( [ x ] )
# 1106 "lib/parser.ml"
     : (Ast.prod_rule_rhs list))

let _menhir_action_68 =
  fun x xs ->
    (
# 253 "<standard.mly>"
    ( x :: xs )
# 1114 "lib/parser.ml"
     : (Ast.prod_rule_rhs list))

let _menhir_print_token : token -> string =
  fun _tok ->
    match _tok with
    | ARROW ->
        "ARROW"
    | ASSIGN ->
        "ASSIGN"
    | BITLIST ->
        "BITLIST"
    | BITS _ ->
        "BITS"
    | BITVECTOR ->
        "BITVECTOR"
    | BOOL ->
        "BOOL"
    | BVAND ->
        "BVAND"
    | BVGT ->
        "BVGT"
    | BVGTE ->
        "BVGTE"
    | BVLT ->
        "BVLT"
    | BVLTE ->
        "BVLTE"
    | BVNOT ->
        "BVNOT"
    | BVOR ->
        "BVOR"
    | BVXOR ->
        "BVXOR"
    | CASE ->
        "CASE"
    | COMMA ->
        "COMMA"
    | DIV ->
        "DIV"
    | DOT ->
        "DOT"
    | EOF ->
        "EOF"
    | EQ ->
        "EQ"
    | FALSE ->
        "FALSE"
    | GT ->
        "GT"
    | GTE ->
        "GTE"
    | ID _ ->
        "ID"
    | INT ->
        "INT"
    | INTEGER _ ->
        "INTEGER"
    | INTTOBITVECTOR ->
        "INTTOBITVECTOR"
    | LAND ->
        "LAND"
    | LCURLY ->
        "LCURLY"
    | LENGTH ->
        "LENGTH"
    | LIMPLIES ->
        "LIMPLIES"
    | LNOT ->
        "LNOT"
    | LOR ->
        "LOR"
    | LPAREN ->
        "LPAREN"
    | LT ->
        "LT"
    | LTE ->
        "LTE"
    | LXOR ->
        "LXOR"
    | MACHINEINT ->
        "MACHINEINT"
    | MINUS ->
        "MINUS"
    | OF ->
        "OF"
    | OPTION ->
        "OPTION"
    | PLUS ->
        "PLUS"
    | PRODUCTION ->
        "PRODUCTION"
    | RCURLY ->
        "RCURLY"
    | RPAREN ->
        "RPAREN"
    | SEMICOLON ->
        "SEMICOLON"
    | STR ->
        "STR"
    | STRING _ ->
        "STRING"
    | TIMES ->
        "TIMES"
    | TRUE ->
        "TRUE"
    | TYPEANNOT ->
        "TYPEANNOT"

let _menhir_fail : unit -> 'a =
  fun () ->
    Printf.eprintf "Internal failure -- please contact the parser generator's developers.\n%!";
    assert false

include struct
  
  [@@@ocaml.warning "-4-37"]
  
  let _menhir_run_134 : type  ttv_stack. ttv_stack -> _ -> _menhir_box_s =
    fun _menhir_stack _v ->
      let d = _v in
      let _v = _menhir_action_61 d in
      MenhirBox_s _v
  
  let rec _menhir_run_137 : type  ttv_stack. (ttv_stack, _menhir_box_s) _menhir_cell1_element -> _ -> _menhir_box_s =
    fun _menhir_stack _v ->
      let MenhirCell1_element (_menhir_stack, _menhir_s, x) = _menhir_stack in
      let xs = _v in
      let _v = _menhir_action_50 x xs in
      _menhir_goto_list_element_ _menhir_stack _v _menhir_s
  
  and _menhir_goto_list_element_ : type  ttv_stack. ttv_stack -> _ -> (ttv_stack, _menhir_box_s) _menhir_state -> _menhir_box_s =
    fun _menhir_stack _v _menhir_s ->
      match _menhir_s with
      | MenhirState136 ->
          _menhir_run_137 _menhir_stack _v
      | MenhirState000 ->
          _menhir_run_134 _menhir_stack _v
      | _ ->
          _menhir_fail ()
  
  let rec _menhir_run_001 : type  ttv_stack. ttv_stack -> _ -> _ -> (ttv_stack, _menhir_box_s) _menhir_state -> _menhir_box_s =
    fun _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s ->
      let _tok = _menhir_lexer _menhir_lexbuf in
      match (_tok : MenhirBasics.token) with
      | ID _v ->
          let _tok = _menhir_lexer _menhir_lexbuf in
          (match (_tok : MenhirBasics.token) with
          | GT ->
              let _tok = _menhir_lexer _menhir_lexbuf in
              let str = _v in
              let _v = _menhir_action_53 str in
              _menhir_goto_nonterminal _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s _tok
          | _ ->
              _eRR ())
      | _ ->
          _eRR ()
  
  and _menhir_goto_nonterminal : type  ttv_stack. ttv_stack -> _ -> _ -> _ -> (ttv_stack, _menhir_box_s) _menhir_state -> _ -> _menhir_box_s =
    fun _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s _tok ->
      match _menhir_s with
      | MenhirState120 ->
          _menhir_run_129 _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s _tok
      | MenhirState132 ->
          _menhir_run_129 _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s _tok
      | MenhirState127 ->
          _menhir_run_129 _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s _tok
      | MenhirState122 ->
          _menhir_run_123 _menhir_stack _menhir_lexbuf _menhir_lexer _v _tok
      | MenhirState020 ->
          _menhir_run_113 _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s _tok
      | MenhirState111 ->
          _menhir_run_113 _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s _tok
      | MenhirState114 ->
          _menhir_run_049 _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s _tok
      | MenhirState023 ->
          _menhir_run_049 _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s _tok
      | MenhirState024 ->
          _menhir_run_049 _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s _tok
      | MenhirState025 ->
          _menhir_run_049 _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s _tok
      | MenhirState026 ->
          _menhir_run_049 _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s _tok
      | MenhirState028 ->
          _menhir_run_049 _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s _tok
      | MenhirState032 ->
          _menhir_run_049 _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s _tok
      | MenhirState035 ->
          _menhir_run_049 _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s _tok
      | MenhirState038 ->
          _menhir_run_049 _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s _tok
      | MenhirState092 ->
          _menhir_run_049 _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s _tok
      | MenhirState090 ->
          _menhir_run_049 _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s _tok
      | MenhirState088 ->
          _menhir_run_049 _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s _tok
      | MenhirState086 ->
          _menhir_run_049 _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s _tok
      | MenhirState084 ->
          _menhir_run_049 _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s _tok
      | MenhirState082 ->
          _menhir_run_049 _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s _tok
      | MenhirState080 ->
          _menhir_run_049 _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s _tok
      | MenhirState078 ->
          _menhir_run_049 _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s _tok
      | MenhirState076 ->
          _menhir_run_049 _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s _tok
      | MenhirState074 ->
          _menhir_run_049 _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s _tok
      | MenhirState072 ->
          _menhir_run_049 _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s _tok
      | MenhirState070 ->
          _menhir_run_049 _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s _tok
      | MenhirState068 ->
          _menhir_run_049 _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s _tok
      | MenhirState066 ->
          _menhir_run_049 _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s _tok
      | MenhirState064 ->
          _menhir_run_049 _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s _tok
      | MenhirState062 ->
          _menhir_run_049 _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s _tok
      | MenhirState060 ->
          _menhir_run_049 _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s _tok
      | MenhirState058 ->
          _menhir_run_049 _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s _tok
      | MenhirState056 ->
          _menhir_run_049 _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s _tok
      | MenhirState054 ->
          _menhir_run_049 _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s _tok
      | MenhirState040 ->
          _menhir_run_049 _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s _tok
      | MenhirState050 ->
          _menhir_run_049 _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s _tok
      | MenhirState041 ->
          _menhir_run_049 _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s _tok
      | MenhirState136 ->
          _menhir_run_005 _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s _tok
      | MenhirState000 ->
          _menhir_run_005 _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s _tok
      | _ ->
          _menhir_fail ()
  
  and _menhir_run_129 : type  ttv_stack. ttv_stack -> _ -> _ -> _ -> (ttv_stack, _menhir_box_s) _menhir_state -> _ -> _menhir_box_s =
    fun _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s _tok ->
      let nt = _v in
      let _v = _menhir_action_40 nt in
      _menhir_goto_grammar_element _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s _tok
  
  and _menhir_goto_grammar_element : type  ttv_stack. ttv_stack -> _ -> _ -> _ -> (ttv_stack, _menhir_box_s) _menhir_state -> _ -> _menhir_box_s =
    fun _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s _tok ->
      match (_tok : MenhirBasics.token) with
      | LT ->
          let _menhir_stack = MenhirCell1_grammar_element (_menhir_stack, _menhir_s, _v) in
          _menhir_run_001 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState132
      | ID _v_0 ->
          let _menhir_stack = MenhirCell1_grammar_element (_menhir_stack, _menhir_s, _v) in
          _menhir_run_121 _menhir_stack _menhir_lexbuf _menhir_lexer _v_0 MenhirState132
      | LCURLY | OPTION | SEMICOLON ->
          let x = _v in
          let _v = _menhir_action_51 x in
          _menhir_goto_nonempty_list_grammar_element_ _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s _tok
      | _ ->
          _eRR ()
  
  and _menhir_run_121 : type  ttv_stack. ttv_stack -> _ -> _ -> _ -> (ttv_stack, _menhir_box_s) _menhir_state -> _menhir_box_s =
    fun _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s ->
      let _menhir_stack = MenhirCell1_ID (_menhir_stack, _menhir_s, _v) in
      let _tok = _menhir_lexer _menhir_lexbuf in
      match (_tok : MenhirBasics.token) with
      | EQ ->
          let _menhir_s = MenhirState122 in
          let _tok = _menhir_lexer _menhir_lexbuf in
          (match (_tok : MenhirBasics.token) with
          | LT ->
              _menhir_run_001 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
          | _ ->
              _eRR ())
      | _ ->
          _eRR ()
  
  and _menhir_goto_nonempty_list_grammar_element_ : type  ttv_stack. ttv_stack -> _ -> _ -> _ -> (ttv_stack, _menhir_box_s) _menhir_state -> _ -> _menhir_box_s =
    fun _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s _tok ->
      match _menhir_s with
      | MenhirState132 ->
          _menhir_run_133 _menhir_stack _menhir_lexbuf _menhir_lexer _v _tok
      | MenhirState120 ->
          _menhir_run_130 _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s _tok
      | MenhirState127 ->
          _menhir_run_130 _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s _tok
      | _ ->
          _menhir_fail ()
  
  and _menhir_run_133 : type  ttv_stack. (ttv_stack, _menhir_box_s) _menhir_cell1_grammar_element -> _ -> _ -> _ -> _ -> _menhir_box_s =
    fun _menhir_stack _menhir_lexbuf _menhir_lexer _v _tok ->
      let MenhirCell1_grammar_element (_menhir_stack, _menhir_s, x) = _menhir_stack in
      let xs = _v in
      let _v = _menhir_action_52 x xs in
      _menhir_goto_nonempty_list_grammar_element_ _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s _tok
  
  and _menhir_run_130 : type  ttv_stack. ttv_stack -> _ -> _ -> _ -> (ttv_stack, _menhir_box_s) _menhir_state -> _ -> _menhir_box_s =
    fun _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s _tok ->
      let _menhir_stack = MenhirCell1_nonempty_list_grammar_element_ (_menhir_stack, _menhir_s, _v) in
      match (_tok : MenhirBasics.token) with
      | LCURLY ->
          _menhir_run_020 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState130
      | OPTION | SEMICOLON ->
          let _v_0 = _menhir_action_58 () in
          _menhir_run_131 _menhir_stack _menhir_lexbuf _menhir_lexer _v_0 _tok
      | _ ->
          _menhir_fail ()
  
  and _menhir_run_020 : type  ttv_stack. ttv_stack -> _ -> _ -> (ttv_stack, _menhir_box_s) _menhir_state -> _menhir_box_s =
    fun _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s ->
      let _menhir_stack = MenhirCell1_LCURLY (_menhir_stack, _menhir_s) in
      let _menhir_s = MenhirState020 in
      let _tok = _menhir_lexer _menhir_lexbuf in
      match (_tok : MenhirBasics.token) with
      | TRUE ->
          _menhir_run_021 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | STRING _v ->
          _menhir_run_022 _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s
      | PLUS ->
          _menhir_run_023 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | MINUS ->
          _menhir_run_024 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | LT ->
          _menhir_run_001 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | LPAREN ->
          _menhir_run_025 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | LNOT ->
          _menhir_run_026 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | LENGTH ->
          _menhir_run_027 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | INTTOBITVECTOR ->
          _menhir_run_029 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | INTEGER _v ->
          _menhir_run_033 _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s
      | FALSE ->
          _menhir_run_034 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | CASE ->
          _menhir_run_035 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | BVNOT ->
          _menhir_run_041 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | BITS _v ->
          _menhir_run_042 _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s
      | _ ->
          _eRR ()
  
  and _menhir_run_021 : type  ttv_stack. ttv_stack -> _ -> _ -> (ttv_stack, _menhir_box_s) _menhir_state -> _menhir_box_s =
    fun _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s ->
      let _tok = _menhir_lexer _menhir_lexbuf in
      let _v = _menhir_action_31 () in
      _menhir_goto_expr _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s _tok
  
  and _menhir_goto_expr : type  ttv_stack. ttv_stack -> _ -> _ -> _ -> (ttv_stack, _menhir_box_s) _menhir_state -> _ -> _menhir_box_s =
    fun _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s _tok ->
      match _menhir_s with
      | MenhirState020 ->
          _menhir_run_116 _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s _tok
      | MenhirState111 ->
          _menhir_run_116 _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s _tok
      | MenhirState114 ->
          _menhir_run_115 _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s _tok
      | MenhirState023 ->
          _menhir_run_107 _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s _tok
      | MenhirState024 ->
          _menhir_run_106 _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s _tok
      | MenhirState025 ->
          _menhir_run_104 _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s _tok
      | MenhirState026 ->
          _menhir_run_100 _menhir_stack _menhir_lexbuf _menhir_lexer _v _tok
      | MenhirState028 ->
          _menhir_run_098 _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s _tok
      | MenhirState032 ->
          _menhir_run_096 _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s _tok
      | MenhirState092 ->
          _menhir_run_093 _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s _tok
      | MenhirState090 ->
          _menhir_run_091 _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s _tok
      | MenhirState088 ->
          _menhir_run_089 _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s _tok
      | MenhirState086 ->
          _menhir_run_087 _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s _tok
      | MenhirState084 ->
          _menhir_run_085 _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s _tok
      | MenhirState082 ->
          _menhir_run_083 _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s _tok
      | MenhirState080 ->
          _menhir_run_081 _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s _tok
      | MenhirState078 ->
          _menhir_run_079 _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s _tok
      | MenhirState076 ->
          _menhir_run_077 _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s _tok
      | MenhirState074 ->
          _menhir_run_075 _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s _tok
      | MenhirState072 ->
          _menhir_run_073 _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s _tok
      | MenhirState070 ->
          _menhir_run_071 _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s _tok
      | MenhirState068 ->
          _menhir_run_069 _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s _tok
      | MenhirState066 ->
          _menhir_run_067 _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s _tok
      | MenhirState064 ->
          _menhir_run_065 _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s _tok
      | MenhirState062 ->
          _menhir_run_063 _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s _tok
      | MenhirState060 ->
          _menhir_run_061 _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s _tok
      | MenhirState058 ->
          _menhir_run_059 _menhir_stack _menhir_lexbuf _menhir_lexer _v _tok
      | MenhirState056 ->
          _menhir_run_057 _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s _tok
      | MenhirState054 ->
          _menhir_run_055 _menhir_stack _menhir_lexbuf _menhir_lexer _v _tok
      | MenhirState040 ->
          _menhir_run_053 _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s _tok
      | MenhirState041 ->
          _menhir_run_052 _menhir_stack _menhir_lexbuf _menhir_lexer _v _tok
      | _ ->
          _menhir_fail ()
  
  and _menhir_run_116 : type  ttv_stack. ttv_stack -> _ -> _ -> _ -> (ttv_stack, _menhir_box_s) _menhir_state -> _ -> _menhir_box_s =
    fun _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s _tok ->
      match (_tok : MenhirBasics.token) with
      | TIMES ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_054 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState116
      | PLUS ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_056 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState116
      | MINUS ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_060 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState116
      | LXOR ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_062 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState116
      | LTE ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_064 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState116
      | LT ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_066 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState116
      | LOR ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_086 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState116
      | LIMPLIES ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_088 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState116
      | LAND ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_068 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState116
      | GTE ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_070 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState116
      | GT ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_072 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState116
      | EQ ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_074 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState116
      | DIV ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_058 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState116
      | BVXOR ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_090 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState116
      | BVOR ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_092 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState116
      | BVLTE ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_076 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState116
      | BVLT ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_078 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState116
      | BVGTE ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_080 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState116
      | BVGT ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_082 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState116
      | BVAND ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_084 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState116
      | SEMICOLON ->
          let e = _v in
          let _v = _menhir_action_63 e in
          _menhir_goto_semantic_constraint _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s
      | _ ->
          _eRR ()
  
  and _menhir_run_054 : type  ttv_stack. ((ttv_stack, _menhir_box_s) _menhir_cell1_expr as 'stack) -> _ -> _ -> ('stack, _menhir_box_s) _menhir_state -> _menhir_box_s =
    fun _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s ->
      let _menhir_stack = MenhirCell1_TIMES (_menhir_stack, _menhir_s) in
      let _menhir_s = MenhirState054 in
      let _tok = _menhir_lexer _menhir_lexbuf in
      match (_tok : MenhirBasics.token) with
      | TRUE ->
          _menhir_run_021 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | STRING _v ->
          _menhir_run_022 _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s
      | PLUS ->
          _menhir_run_023 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | MINUS ->
          _menhir_run_024 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | LT ->
          _menhir_run_001 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | LPAREN ->
          _menhir_run_025 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | LNOT ->
          _menhir_run_026 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | LENGTH ->
          _menhir_run_027 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | INTTOBITVECTOR ->
          _menhir_run_029 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | INTEGER _v ->
          _menhir_run_033 _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s
      | FALSE ->
          _menhir_run_034 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | CASE ->
          _menhir_run_035 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | BVNOT ->
          _menhir_run_041 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | BITS _v ->
          _menhir_run_042 _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s
      | _ ->
          _eRR ()
  
  and _menhir_run_022 : type  ttv_stack. ttv_stack -> _ -> _ -> _ -> (ttv_stack, _menhir_box_s) _menhir_state -> _menhir_box_s =
    fun _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s ->
      let _tok = _menhir_lexer _menhir_lexbuf in
      let s = _v in
      let _v = _menhir_action_30 s in
      _menhir_goto_expr _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s _tok
  
  and _menhir_run_023 : type  ttv_stack. ttv_stack -> _ -> _ -> (ttv_stack, _menhir_box_s) _menhir_state -> _menhir_box_s =
    fun _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s ->
      let _menhir_stack = MenhirCell1_PLUS (_menhir_stack, _menhir_s) in
      let _menhir_s = MenhirState023 in
      let _tok = _menhir_lexer _menhir_lexbuf in
      match (_tok : MenhirBasics.token) with
      | TRUE ->
          _menhir_run_021 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | STRING _v ->
          _menhir_run_022 _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s
      | PLUS ->
          _menhir_run_023 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | MINUS ->
          _menhir_run_024 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | LT ->
          _menhir_run_001 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | LPAREN ->
          _menhir_run_025 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | LNOT ->
          _menhir_run_026 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | LENGTH ->
          _menhir_run_027 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | INTTOBITVECTOR ->
          _menhir_run_029 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | INTEGER _v ->
          _menhir_run_033 _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s
      | FALSE ->
          _menhir_run_034 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | CASE ->
          _menhir_run_035 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | BVNOT ->
          _menhir_run_041 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | BITS _v ->
          _menhir_run_042 _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s
      | _ ->
          _eRR ()
  
  and _menhir_run_024 : type  ttv_stack. ttv_stack -> _ -> _ -> (ttv_stack, _menhir_box_s) _menhir_state -> _menhir_box_s =
    fun _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s ->
      let _menhir_stack = MenhirCell1_MINUS (_menhir_stack, _menhir_s) in
      let _menhir_s = MenhirState024 in
      let _tok = _menhir_lexer _menhir_lexbuf in
      match (_tok : MenhirBasics.token) with
      | TRUE ->
          _menhir_run_021 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | STRING _v ->
          _menhir_run_022 _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s
      | PLUS ->
          _menhir_run_023 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | MINUS ->
          _menhir_run_024 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | LT ->
          _menhir_run_001 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | LPAREN ->
          _menhir_run_025 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | LNOT ->
          _menhir_run_026 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | LENGTH ->
          _menhir_run_027 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | INTTOBITVECTOR ->
          _menhir_run_029 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | INTEGER _v ->
          _menhir_run_033 _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s
      | FALSE ->
          _menhir_run_034 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | CASE ->
          _menhir_run_035 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | BVNOT ->
          _menhir_run_041 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | BITS _v ->
          _menhir_run_042 _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s
      | _ ->
          _eRR ()
  
  and _menhir_run_025 : type  ttv_stack. ttv_stack -> _ -> _ -> (ttv_stack, _menhir_box_s) _menhir_state -> _menhir_box_s =
    fun _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s ->
      let _tok = _menhir_lexer _menhir_lexbuf in
      match (_tok : MenhirBasics.token) with
      | TRUE ->
          let _menhir_stack = MenhirCell1_LPAREN (_menhir_stack, _menhir_s) in
          _menhir_run_021 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState025
      | STRING _v ->
          let _menhir_stack = MenhirCell1_LPAREN (_menhir_stack, _menhir_s) in
          _menhir_run_022 _menhir_stack _menhir_lexbuf _menhir_lexer _v MenhirState025
      | PLUS ->
          let _menhir_stack = MenhirCell1_LPAREN (_menhir_stack, _menhir_s) in
          _menhir_run_023 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState025
      | MINUS ->
          let _menhir_stack = MenhirCell1_LPAREN (_menhir_stack, _menhir_s) in
          _menhir_run_024 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState025
      | LT ->
          let _menhir_stack = MenhirCell1_LPAREN (_menhir_stack, _menhir_s) in
          _menhir_run_001 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState025
      | LPAREN ->
          let _menhir_stack = MenhirCell1_LPAREN (_menhir_stack, _menhir_s) in
          _menhir_run_025 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState025
      | LNOT ->
          let _menhir_stack = MenhirCell1_LPAREN (_menhir_stack, _menhir_s) in
          _menhir_run_026 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState025
      | LENGTH ->
          let _menhir_stack = MenhirCell1_LPAREN (_menhir_stack, _menhir_s) in
          _menhir_run_027 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState025
      | INTTOBITVECTOR ->
          let _menhir_stack = MenhirCell1_LPAREN (_menhir_stack, _menhir_s) in
          _menhir_run_029 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState025
      | INTEGER _v ->
          let _menhir_stack = MenhirCell1_LPAREN (_menhir_stack, _menhir_s) in
          _menhir_run_033 _menhir_stack _menhir_lexbuf _menhir_lexer _v MenhirState025
      | FALSE ->
          let _menhir_stack = MenhirCell1_LPAREN (_menhir_stack, _menhir_s) in
          _menhir_run_034 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState025
      | CASE ->
          let _menhir_stack = MenhirCell1_LPAREN (_menhir_stack, _menhir_s) in
          _menhir_run_035 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState025
      | BVNOT ->
          let _menhir_stack = MenhirCell1_LPAREN (_menhir_stack, _menhir_s) in
          _menhir_run_041 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState025
      | BITS _v ->
          let _menhir_stack = MenhirCell1_LPAREN (_menhir_stack, _menhir_s) in
          _menhir_run_042 _menhir_stack _menhir_lexbuf _menhir_lexer _v MenhirState025
      | BITLIST ->
          let _tok = _menhir_lexer _menhir_lexbuf in
          (match (_tok : MenhirBasics.token) with
          | BITS _v ->
              let _tok = _menhir_lexer _menhir_lexbuf in
              (match (_tok : MenhirBasics.token) with
              | RPAREN ->
                  let _tok = _menhir_lexer _menhir_lexbuf in
                  let bl = _v in
                  let _v = _menhir_action_34 bl in
                  _menhir_goto_expr _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s _tok
              | _ ->
                  _eRR ())
          | _ ->
              _eRR ())
      | _ ->
          _eRR ()
  
  and _menhir_run_026 : type  ttv_stack. ttv_stack -> _ -> _ -> (ttv_stack, _menhir_box_s) _menhir_state -> _menhir_box_s =
    fun _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s ->
      let _menhir_stack = MenhirCell1_LNOT (_menhir_stack, _menhir_s) in
      let _menhir_s = MenhirState026 in
      let _tok = _menhir_lexer _menhir_lexbuf in
      match (_tok : MenhirBasics.token) with
      | TRUE ->
          _menhir_run_021 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | STRING _v ->
          _menhir_run_022 _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s
      | PLUS ->
          _menhir_run_023 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | MINUS ->
          _menhir_run_024 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | LT ->
          _menhir_run_001 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | LPAREN ->
          _menhir_run_025 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | LNOT ->
          _menhir_run_026 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | LENGTH ->
          _menhir_run_027 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | INTTOBITVECTOR ->
          _menhir_run_029 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | INTEGER _v ->
          _menhir_run_033 _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s
      | FALSE ->
          _menhir_run_034 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | CASE ->
          _menhir_run_035 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | BVNOT ->
          _menhir_run_041 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | BITS _v ->
          _menhir_run_042 _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s
      | _ ->
          _eRR ()
  
  and _menhir_run_027 : type  ttv_stack. ttv_stack -> _ -> _ -> (ttv_stack, _menhir_box_s) _menhir_state -> _menhir_box_s =
    fun _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s ->
      let _menhir_stack = MenhirCell1_LENGTH (_menhir_stack, _menhir_s) in
      let _tok = _menhir_lexer _menhir_lexbuf in
      match (_tok : MenhirBasics.token) with
      | LPAREN ->
          let _menhir_s = MenhirState028 in
          let _tok = _menhir_lexer _menhir_lexbuf in
          (match (_tok : MenhirBasics.token) with
          | TRUE ->
              _menhir_run_021 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
          | STRING _v ->
              _menhir_run_022 _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s
          | PLUS ->
              _menhir_run_023 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
          | MINUS ->
              _menhir_run_024 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
          | LT ->
              _menhir_run_001 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
          | LPAREN ->
              _menhir_run_025 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
          | LNOT ->
              _menhir_run_026 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
          | LENGTH ->
              _menhir_run_027 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
          | INTTOBITVECTOR ->
              _menhir_run_029 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
          | INTEGER _v ->
              _menhir_run_033 _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s
          | FALSE ->
              _menhir_run_034 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
          | CASE ->
              _menhir_run_035 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
          | BVNOT ->
              _menhir_run_041 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
          | BITS _v ->
              _menhir_run_042 _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s
          | _ ->
              _eRR ())
      | _ ->
          _eRR ()
  
  and _menhir_run_029 : type  ttv_stack. ttv_stack -> _ -> _ -> (ttv_stack, _menhir_box_s) _menhir_state -> _menhir_box_s =
    fun _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s ->
      let _menhir_stack = MenhirCell1_INTTOBITVECTOR (_menhir_stack, _menhir_s) in
      let _tok = _menhir_lexer _menhir_lexbuf in
      match (_tok : MenhirBasics.token) with
      | LPAREN ->
          let _tok = _menhir_lexer _menhir_lexbuf in
          (match (_tok : MenhirBasics.token) with
          | INTEGER _v ->
              let _menhir_stack = MenhirCell0_INTEGER (_menhir_stack, _v) in
              let _tok = _menhir_lexer _menhir_lexbuf in
              (match (_tok : MenhirBasics.token) with
              | COMMA ->
                  let _menhir_s = MenhirState032 in
                  let _tok = _menhir_lexer _menhir_lexbuf in
                  (match (_tok : MenhirBasics.token) with
                  | TRUE ->
                      _menhir_run_021 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
                  | STRING _v ->
                      _menhir_run_022 _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s
                  | PLUS ->
                      _menhir_run_023 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
                  | MINUS ->
                      _menhir_run_024 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
                  | LT ->
                      _menhir_run_001 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
                  | LPAREN ->
                      _menhir_run_025 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
                  | LNOT ->
                      _menhir_run_026 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
                  | LENGTH ->
                      _menhir_run_027 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
                  | INTTOBITVECTOR ->
                      _menhir_run_029 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
                  | INTEGER _v ->
                      _menhir_run_033 _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s
                  | FALSE ->
                      _menhir_run_034 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
                  | CASE ->
                      _menhir_run_035 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
                  | BVNOT ->
                      _menhir_run_041 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
                  | BITS _v ->
                      _menhir_run_042 _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s
                  | _ ->
                      _eRR ())
              | _ ->
                  _eRR ())
          | _ ->
              _eRR ())
      | _ ->
          _eRR ()
  
  and _menhir_run_033 : type  ttv_stack. ttv_stack -> _ -> _ -> _ -> (ttv_stack, _menhir_box_s) _menhir_state -> _menhir_box_s =
    fun _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s ->
      let _tok = _menhir_lexer _menhir_lexbuf in
      let i = _v in
      let _v = _menhir_action_29 i in
      _menhir_goto_expr _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s _tok
  
  and _menhir_run_034 : type  ttv_stack. ttv_stack -> _ -> _ -> (ttv_stack, _menhir_box_s) _menhir_state -> _menhir_box_s =
    fun _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s ->
      let _tok = _menhir_lexer _menhir_lexbuf in
      let _v = _menhir_action_32 () in
      _menhir_goto_expr _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s _tok
  
  and _menhir_run_035 : type  ttv_stack. ttv_stack -> _ -> _ -> (ttv_stack, _menhir_box_s) _menhir_state -> _menhir_box_s =
    fun _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s ->
      let _menhir_stack = MenhirCell1_CASE (_menhir_stack, _menhir_s) in
      let _menhir_s = MenhirState035 in
      let _tok = _menhir_lexer _menhir_lexbuf in
      match (_tok : MenhirBasics.token) with
      | LT ->
          _menhir_run_001 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | _ ->
          _eRR ()
  
  and _menhir_run_041 : type  ttv_stack. ttv_stack -> _ -> _ -> (ttv_stack, _menhir_box_s) _menhir_state -> _menhir_box_s =
    fun _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s ->
      let _menhir_stack = MenhirCell1_BVNOT (_menhir_stack, _menhir_s) in
      let _menhir_s = MenhirState041 in
      let _tok = _menhir_lexer _menhir_lexbuf in
      match (_tok : MenhirBasics.token) with
      | TRUE ->
          _menhir_run_021 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | STRING _v ->
          _menhir_run_022 _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s
      | PLUS ->
          _menhir_run_023 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | MINUS ->
          _menhir_run_024 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | LT ->
          _menhir_run_001 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | LPAREN ->
          _menhir_run_025 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | LNOT ->
          _menhir_run_026 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | LENGTH ->
          _menhir_run_027 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | INTTOBITVECTOR ->
          _menhir_run_029 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | INTEGER _v ->
          _menhir_run_033 _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s
      | FALSE ->
          _menhir_run_034 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | CASE ->
          _menhir_run_035 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | BVNOT ->
          _menhir_run_041 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | BITS _v ->
          _menhir_run_042 _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s
      | _ ->
          _eRR ()
  
  and _menhir_run_042 : type  ttv_stack. ttv_stack -> _ -> _ -> _ -> (ttv_stack, _menhir_box_s) _menhir_state -> _menhir_box_s =
    fun _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s ->
      let _tok = _menhir_lexer _menhir_lexbuf in
      let bv = _v in
      let _v = _menhir_action_33 bv in
      _menhir_goto_expr _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s _tok
  
  and _menhir_run_056 : type  ttv_stack. ((ttv_stack, _menhir_box_s) _menhir_cell1_expr as 'stack) -> _ -> _ -> ('stack, _menhir_box_s) _menhir_state -> _menhir_box_s =
    fun _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s ->
      let _menhir_stack = MenhirCell1_PLUS (_menhir_stack, _menhir_s) in
      let _menhir_s = MenhirState056 in
      let _tok = _menhir_lexer _menhir_lexbuf in
      match (_tok : MenhirBasics.token) with
      | TRUE ->
          _menhir_run_021 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | STRING _v ->
          _menhir_run_022 _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s
      | PLUS ->
          _menhir_run_023 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | MINUS ->
          _menhir_run_024 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | LT ->
          _menhir_run_001 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | LPAREN ->
          _menhir_run_025 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | LNOT ->
          _menhir_run_026 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | LENGTH ->
          _menhir_run_027 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | INTTOBITVECTOR ->
          _menhir_run_029 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | INTEGER _v ->
          _menhir_run_033 _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s
      | FALSE ->
          _menhir_run_034 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | CASE ->
          _menhir_run_035 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | BVNOT ->
          _menhir_run_041 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | BITS _v ->
          _menhir_run_042 _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s
      | _ ->
          _eRR ()
  
  and _menhir_run_060 : type  ttv_stack. ((ttv_stack, _menhir_box_s) _menhir_cell1_expr as 'stack) -> _ -> _ -> ('stack, _menhir_box_s) _menhir_state -> _menhir_box_s =
    fun _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s ->
      let _menhir_stack = MenhirCell1_MINUS (_menhir_stack, _menhir_s) in
      let _menhir_s = MenhirState060 in
      let _tok = _menhir_lexer _menhir_lexbuf in
      match (_tok : MenhirBasics.token) with
      | TRUE ->
          _menhir_run_021 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | STRING _v ->
          _menhir_run_022 _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s
      | PLUS ->
          _menhir_run_023 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | MINUS ->
          _menhir_run_024 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | LT ->
          _menhir_run_001 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | LPAREN ->
          _menhir_run_025 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | LNOT ->
          _menhir_run_026 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | LENGTH ->
          _menhir_run_027 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | INTTOBITVECTOR ->
          _menhir_run_029 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | INTEGER _v ->
          _menhir_run_033 _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s
      | FALSE ->
          _menhir_run_034 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | CASE ->
          _menhir_run_035 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | BVNOT ->
          _menhir_run_041 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | BITS _v ->
          _menhir_run_042 _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s
      | _ ->
          _eRR ()
  
  and _menhir_run_062 : type  ttv_stack. ((ttv_stack, _menhir_box_s) _menhir_cell1_expr as 'stack) -> _ -> _ -> ('stack, _menhir_box_s) _menhir_state -> _menhir_box_s =
    fun _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s ->
      let _menhir_stack = MenhirCell1_LXOR (_menhir_stack, _menhir_s) in
      let _menhir_s = MenhirState062 in
      let _tok = _menhir_lexer _menhir_lexbuf in
      match (_tok : MenhirBasics.token) with
      | TRUE ->
          _menhir_run_021 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | STRING _v ->
          _menhir_run_022 _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s
      | PLUS ->
          _menhir_run_023 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | MINUS ->
          _menhir_run_024 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | LT ->
          _menhir_run_001 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | LPAREN ->
          _menhir_run_025 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | LNOT ->
          _menhir_run_026 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | LENGTH ->
          _menhir_run_027 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | INTTOBITVECTOR ->
          _menhir_run_029 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | INTEGER _v ->
          _menhir_run_033 _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s
      | FALSE ->
          _menhir_run_034 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | CASE ->
          _menhir_run_035 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | BVNOT ->
          _menhir_run_041 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | BITS _v ->
          _menhir_run_042 _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s
      | _ ->
          _eRR ()
  
  and _menhir_run_064 : type  ttv_stack. ((ttv_stack, _menhir_box_s) _menhir_cell1_expr as 'stack) -> _ -> _ -> ('stack, _menhir_box_s) _menhir_state -> _menhir_box_s =
    fun _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s ->
      let _menhir_stack = MenhirCell1_LTE (_menhir_stack, _menhir_s) in
      let _menhir_s = MenhirState064 in
      let _tok = _menhir_lexer _menhir_lexbuf in
      match (_tok : MenhirBasics.token) with
      | TRUE ->
          _menhir_run_021 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | STRING _v ->
          _menhir_run_022 _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s
      | PLUS ->
          _menhir_run_023 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | MINUS ->
          _menhir_run_024 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | LT ->
          _menhir_run_001 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | LPAREN ->
          _menhir_run_025 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | LNOT ->
          _menhir_run_026 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | LENGTH ->
          _menhir_run_027 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | INTTOBITVECTOR ->
          _menhir_run_029 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | INTEGER _v ->
          _menhir_run_033 _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s
      | FALSE ->
          _menhir_run_034 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | CASE ->
          _menhir_run_035 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | BVNOT ->
          _menhir_run_041 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | BITS _v ->
          _menhir_run_042 _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s
      | _ ->
          _eRR ()
  
  and _menhir_run_066 : type  ttv_stack. ((ttv_stack, _menhir_box_s) _menhir_cell1_expr as 'stack) -> _ -> _ -> ('stack, _menhir_box_s) _menhir_state -> _menhir_box_s =
    fun _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s ->
      let _menhir_stack = MenhirCell1_LT (_menhir_stack, _menhir_s) in
      let _menhir_s = MenhirState066 in
      let _tok = _menhir_lexer _menhir_lexbuf in
      match (_tok : MenhirBasics.token) with
      | TRUE ->
          _menhir_run_021 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | STRING _v ->
          _menhir_run_022 _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s
      | PLUS ->
          _menhir_run_023 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | MINUS ->
          _menhir_run_024 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | LT ->
          _menhir_run_001 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | LPAREN ->
          _menhir_run_025 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | LNOT ->
          _menhir_run_026 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | LENGTH ->
          _menhir_run_027 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | INTTOBITVECTOR ->
          _menhir_run_029 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | INTEGER _v ->
          _menhir_run_033 _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s
      | FALSE ->
          _menhir_run_034 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | CASE ->
          _menhir_run_035 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | BVNOT ->
          _menhir_run_041 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | BITS _v ->
          _menhir_run_042 _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s
      | _ ->
          _eRR ()
  
  and _menhir_run_086 : type  ttv_stack. ((ttv_stack, _menhir_box_s) _menhir_cell1_expr as 'stack) -> _ -> _ -> ('stack, _menhir_box_s) _menhir_state -> _menhir_box_s =
    fun _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s ->
      let _menhir_stack = MenhirCell1_LOR (_menhir_stack, _menhir_s) in
      let _menhir_s = MenhirState086 in
      let _tok = _menhir_lexer _menhir_lexbuf in
      match (_tok : MenhirBasics.token) with
      | TRUE ->
          _menhir_run_021 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | STRING _v ->
          _menhir_run_022 _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s
      | PLUS ->
          _menhir_run_023 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | MINUS ->
          _menhir_run_024 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | LT ->
          _menhir_run_001 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | LPAREN ->
          _menhir_run_025 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | LNOT ->
          _menhir_run_026 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | LENGTH ->
          _menhir_run_027 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | INTTOBITVECTOR ->
          _menhir_run_029 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | INTEGER _v ->
          _menhir_run_033 _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s
      | FALSE ->
          _menhir_run_034 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | CASE ->
          _menhir_run_035 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | BVNOT ->
          _menhir_run_041 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | BITS _v ->
          _menhir_run_042 _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s
      | _ ->
          _eRR ()
  
  and _menhir_run_088 : type  ttv_stack. ((ttv_stack, _menhir_box_s) _menhir_cell1_expr as 'stack) -> _ -> _ -> ('stack, _menhir_box_s) _menhir_state -> _menhir_box_s =
    fun _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s ->
      let _menhir_stack = MenhirCell1_LIMPLIES (_menhir_stack, _menhir_s) in
      let _menhir_s = MenhirState088 in
      let _tok = _menhir_lexer _menhir_lexbuf in
      match (_tok : MenhirBasics.token) with
      | TRUE ->
          _menhir_run_021 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | STRING _v ->
          _menhir_run_022 _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s
      | PLUS ->
          _menhir_run_023 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | MINUS ->
          _menhir_run_024 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | LT ->
          _menhir_run_001 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | LPAREN ->
          _menhir_run_025 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | LNOT ->
          _menhir_run_026 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | LENGTH ->
          _menhir_run_027 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | INTTOBITVECTOR ->
          _menhir_run_029 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | INTEGER _v ->
          _menhir_run_033 _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s
      | FALSE ->
          _menhir_run_034 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | CASE ->
          _menhir_run_035 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | BVNOT ->
          _menhir_run_041 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | BITS _v ->
          _menhir_run_042 _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s
      | _ ->
          _eRR ()
  
  and _menhir_run_068 : type  ttv_stack. ((ttv_stack, _menhir_box_s) _menhir_cell1_expr as 'stack) -> _ -> _ -> ('stack, _menhir_box_s) _menhir_state -> _menhir_box_s =
    fun _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s ->
      let _menhir_stack = MenhirCell1_LAND (_menhir_stack, _menhir_s) in
      let _menhir_s = MenhirState068 in
      let _tok = _menhir_lexer _menhir_lexbuf in
      match (_tok : MenhirBasics.token) with
      | TRUE ->
          _menhir_run_021 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | STRING _v ->
          _menhir_run_022 _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s
      | PLUS ->
          _menhir_run_023 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | MINUS ->
          _menhir_run_024 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | LT ->
          _menhir_run_001 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | LPAREN ->
          _menhir_run_025 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | LNOT ->
          _menhir_run_026 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | LENGTH ->
          _menhir_run_027 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | INTTOBITVECTOR ->
          _menhir_run_029 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | INTEGER _v ->
          _menhir_run_033 _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s
      | FALSE ->
          _menhir_run_034 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | CASE ->
          _menhir_run_035 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | BVNOT ->
          _menhir_run_041 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | BITS _v ->
          _menhir_run_042 _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s
      | _ ->
          _eRR ()
  
  and _menhir_run_070 : type  ttv_stack. ((ttv_stack, _menhir_box_s) _menhir_cell1_expr as 'stack) -> _ -> _ -> ('stack, _menhir_box_s) _menhir_state -> _menhir_box_s =
    fun _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s ->
      let _menhir_stack = MenhirCell1_GTE (_menhir_stack, _menhir_s) in
      let _menhir_s = MenhirState070 in
      let _tok = _menhir_lexer _menhir_lexbuf in
      match (_tok : MenhirBasics.token) with
      | TRUE ->
          _menhir_run_021 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | STRING _v ->
          _menhir_run_022 _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s
      | PLUS ->
          _menhir_run_023 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | MINUS ->
          _menhir_run_024 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | LT ->
          _menhir_run_001 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | LPAREN ->
          _menhir_run_025 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | LNOT ->
          _menhir_run_026 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | LENGTH ->
          _menhir_run_027 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | INTTOBITVECTOR ->
          _menhir_run_029 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | INTEGER _v ->
          _menhir_run_033 _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s
      | FALSE ->
          _menhir_run_034 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | CASE ->
          _menhir_run_035 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | BVNOT ->
          _menhir_run_041 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | BITS _v ->
          _menhir_run_042 _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s
      | _ ->
          _eRR ()
  
  and _menhir_run_072 : type  ttv_stack. ((ttv_stack, _menhir_box_s) _menhir_cell1_expr as 'stack) -> _ -> _ -> ('stack, _menhir_box_s) _menhir_state -> _menhir_box_s =
    fun _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s ->
      let _menhir_stack = MenhirCell1_GT (_menhir_stack, _menhir_s) in
      let _menhir_s = MenhirState072 in
      let _tok = _menhir_lexer _menhir_lexbuf in
      match (_tok : MenhirBasics.token) with
      | TRUE ->
          _menhir_run_021 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | STRING _v ->
          _menhir_run_022 _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s
      | PLUS ->
          _menhir_run_023 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | MINUS ->
          _menhir_run_024 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | LT ->
          _menhir_run_001 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | LPAREN ->
          _menhir_run_025 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | LNOT ->
          _menhir_run_026 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | LENGTH ->
          _menhir_run_027 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | INTTOBITVECTOR ->
          _menhir_run_029 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | INTEGER _v ->
          _menhir_run_033 _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s
      | FALSE ->
          _menhir_run_034 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | CASE ->
          _menhir_run_035 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | BVNOT ->
          _menhir_run_041 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | BITS _v ->
          _menhir_run_042 _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s
      | _ ->
          _eRR ()
  
  and _menhir_run_074 : type  ttv_stack. ((ttv_stack, _menhir_box_s) _menhir_cell1_expr as 'stack) -> _ -> _ -> ('stack, _menhir_box_s) _menhir_state -> _menhir_box_s =
    fun _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s ->
      let _menhir_stack = MenhirCell1_EQ (_menhir_stack, _menhir_s) in
      let _menhir_s = MenhirState074 in
      let _tok = _menhir_lexer _menhir_lexbuf in
      match (_tok : MenhirBasics.token) with
      | TRUE ->
          _menhir_run_021 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | STRING _v ->
          _menhir_run_022 _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s
      | PLUS ->
          _menhir_run_023 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | MINUS ->
          _menhir_run_024 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | LT ->
          _menhir_run_001 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | LPAREN ->
          _menhir_run_025 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | LNOT ->
          _menhir_run_026 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | LENGTH ->
          _menhir_run_027 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | INTTOBITVECTOR ->
          _menhir_run_029 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | INTEGER _v ->
          _menhir_run_033 _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s
      | FALSE ->
          _menhir_run_034 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | CASE ->
          _menhir_run_035 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | BVNOT ->
          _menhir_run_041 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | BITS _v ->
          _menhir_run_042 _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s
      | _ ->
          _eRR ()
  
  and _menhir_run_058 : type  ttv_stack. ((ttv_stack, _menhir_box_s) _menhir_cell1_expr as 'stack) -> _ -> _ -> ('stack, _menhir_box_s) _menhir_state -> _menhir_box_s =
    fun _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s ->
      let _menhir_stack = MenhirCell1_DIV (_menhir_stack, _menhir_s) in
      let _menhir_s = MenhirState058 in
      let _tok = _menhir_lexer _menhir_lexbuf in
      match (_tok : MenhirBasics.token) with
      | TRUE ->
          _menhir_run_021 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | STRING _v ->
          _menhir_run_022 _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s
      | PLUS ->
          _menhir_run_023 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | MINUS ->
          _menhir_run_024 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | LT ->
          _menhir_run_001 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | LPAREN ->
          _menhir_run_025 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | LNOT ->
          _menhir_run_026 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | LENGTH ->
          _menhir_run_027 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | INTTOBITVECTOR ->
          _menhir_run_029 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | INTEGER _v ->
          _menhir_run_033 _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s
      | FALSE ->
          _menhir_run_034 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | CASE ->
          _menhir_run_035 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | BVNOT ->
          _menhir_run_041 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | BITS _v ->
          _menhir_run_042 _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s
      | _ ->
          _eRR ()
  
  and _menhir_run_090 : type  ttv_stack. ((ttv_stack, _menhir_box_s) _menhir_cell1_expr as 'stack) -> _ -> _ -> ('stack, _menhir_box_s) _menhir_state -> _menhir_box_s =
    fun _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s ->
      let _menhir_stack = MenhirCell1_BVXOR (_menhir_stack, _menhir_s) in
      let _menhir_s = MenhirState090 in
      let _tok = _menhir_lexer _menhir_lexbuf in
      match (_tok : MenhirBasics.token) with
      | TRUE ->
          _menhir_run_021 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | STRING _v ->
          _menhir_run_022 _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s
      | PLUS ->
          _menhir_run_023 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | MINUS ->
          _menhir_run_024 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | LT ->
          _menhir_run_001 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | LPAREN ->
          _menhir_run_025 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | LNOT ->
          _menhir_run_026 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | LENGTH ->
          _menhir_run_027 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | INTTOBITVECTOR ->
          _menhir_run_029 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | INTEGER _v ->
          _menhir_run_033 _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s
      | FALSE ->
          _menhir_run_034 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | CASE ->
          _menhir_run_035 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | BVNOT ->
          _menhir_run_041 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | BITS _v ->
          _menhir_run_042 _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s
      | _ ->
          _eRR ()
  
  and _menhir_run_092 : type  ttv_stack. ((ttv_stack, _menhir_box_s) _menhir_cell1_expr as 'stack) -> _ -> _ -> ('stack, _menhir_box_s) _menhir_state -> _menhir_box_s =
    fun _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s ->
      let _menhir_stack = MenhirCell1_BVOR (_menhir_stack, _menhir_s) in
      let _menhir_s = MenhirState092 in
      let _tok = _menhir_lexer _menhir_lexbuf in
      match (_tok : MenhirBasics.token) with
      | TRUE ->
          _menhir_run_021 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | STRING _v ->
          _menhir_run_022 _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s
      | PLUS ->
          _menhir_run_023 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | MINUS ->
          _menhir_run_024 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | LT ->
          _menhir_run_001 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | LPAREN ->
          _menhir_run_025 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | LNOT ->
          _menhir_run_026 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | LENGTH ->
          _menhir_run_027 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | INTTOBITVECTOR ->
          _menhir_run_029 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | INTEGER _v ->
          _menhir_run_033 _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s
      | FALSE ->
          _menhir_run_034 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | CASE ->
          _menhir_run_035 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | BVNOT ->
          _menhir_run_041 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | BITS _v ->
          _menhir_run_042 _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s
      | _ ->
          _eRR ()
  
  and _menhir_run_076 : type  ttv_stack. ((ttv_stack, _menhir_box_s) _menhir_cell1_expr as 'stack) -> _ -> _ -> ('stack, _menhir_box_s) _menhir_state -> _menhir_box_s =
    fun _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s ->
      let _menhir_stack = MenhirCell1_BVLTE (_menhir_stack, _menhir_s) in
      let _menhir_s = MenhirState076 in
      let _tok = _menhir_lexer _menhir_lexbuf in
      match (_tok : MenhirBasics.token) with
      | TRUE ->
          _menhir_run_021 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | STRING _v ->
          _menhir_run_022 _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s
      | PLUS ->
          _menhir_run_023 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | MINUS ->
          _menhir_run_024 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | LT ->
          _menhir_run_001 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | LPAREN ->
          _menhir_run_025 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | LNOT ->
          _menhir_run_026 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | LENGTH ->
          _menhir_run_027 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | INTTOBITVECTOR ->
          _menhir_run_029 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | INTEGER _v ->
          _menhir_run_033 _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s
      | FALSE ->
          _menhir_run_034 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | CASE ->
          _menhir_run_035 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | BVNOT ->
          _menhir_run_041 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | BITS _v ->
          _menhir_run_042 _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s
      | _ ->
          _eRR ()
  
  and _menhir_run_078 : type  ttv_stack. ((ttv_stack, _menhir_box_s) _menhir_cell1_expr as 'stack) -> _ -> _ -> ('stack, _menhir_box_s) _menhir_state -> _menhir_box_s =
    fun _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s ->
      let _menhir_stack = MenhirCell1_BVLT (_menhir_stack, _menhir_s) in
      let _menhir_s = MenhirState078 in
      let _tok = _menhir_lexer _menhir_lexbuf in
      match (_tok : MenhirBasics.token) with
      | TRUE ->
          _menhir_run_021 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | STRING _v ->
          _menhir_run_022 _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s
      | PLUS ->
          _menhir_run_023 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | MINUS ->
          _menhir_run_024 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | LT ->
          _menhir_run_001 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | LPAREN ->
          _menhir_run_025 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | LNOT ->
          _menhir_run_026 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | LENGTH ->
          _menhir_run_027 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | INTTOBITVECTOR ->
          _menhir_run_029 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | INTEGER _v ->
          _menhir_run_033 _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s
      | FALSE ->
          _menhir_run_034 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | CASE ->
          _menhir_run_035 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | BVNOT ->
          _menhir_run_041 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | BITS _v ->
          _menhir_run_042 _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s
      | _ ->
          _eRR ()
  
  and _menhir_run_080 : type  ttv_stack. ((ttv_stack, _menhir_box_s) _menhir_cell1_expr as 'stack) -> _ -> _ -> ('stack, _menhir_box_s) _menhir_state -> _menhir_box_s =
    fun _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s ->
      let _menhir_stack = MenhirCell1_BVGTE (_menhir_stack, _menhir_s) in
      let _menhir_s = MenhirState080 in
      let _tok = _menhir_lexer _menhir_lexbuf in
      match (_tok : MenhirBasics.token) with
      | TRUE ->
          _menhir_run_021 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | STRING _v ->
          _menhir_run_022 _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s
      | PLUS ->
          _menhir_run_023 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | MINUS ->
          _menhir_run_024 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | LT ->
          _menhir_run_001 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | LPAREN ->
          _menhir_run_025 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | LNOT ->
          _menhir_run_026 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | LENGTH ->
          _menhir_run_027 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | INTTOBITVECTOR ->
          _menhir_run_029 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | INTEGER _v ->
          _menhir_run_033 _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s
      | FALSE ->
          _menhir_run_034 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | CASE ->
          _menhir_run_035 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | BVNOT ->
          _menhir_run_041 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | BITS _v ->
          _menhir_run_042 _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s
      | _ ->
          _eRR ()
  
  and _menhir_run_082 : type  ttv_stack. ((ttv_stack, _menhir_box_s) _menhir_cell1_expr as 'stack) -> _ -> _ -> ('stack, _menhir_box_s) _menhir_state -> _menhir_box_s =
    fun _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s ->
      let _menhir_stack = MenhirCell1_BVGT (_menhir_stack, _menhir_s) in
      let _menhir_s = MenhirState082 in
      let _tok = _menhir_lexer _menhir_lexbuf in
      match (_tok : MenhirBasics.token) with
      | TRUE ->
          _menhir_run_021 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | STRING _v ->
          _menhir_run_022 _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s
      | PLUS ->
          _menhir_run_023 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | MINUS ->
          _menhir_run_024 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | LT ->
          _menhir_run_001 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | LPAREN ->
          _menhir_run_025 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | LNOT ->
          _menhir_run_026 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | LENGTH ->
          _menhir_run_027 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | INTTOBITVECTOR ->
          _menhir_run_029 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | INTEGER _v ->
          _menhir_run_033 _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s
      | FALSE ->
          _menhir_run_034 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | CASE ->
          _menhir_run_035 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | BVNOT ->
          _menhir_run_041 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | BITS _v ->
          _menhir_run_042 _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s
      | _ ->
          _eRR ()
  
  and _menhir_run_084 : type  ttv_stack. ((ttv_stack, _menhir_box_s) _menhir_cell1_expr as 'stack) -> _ -> _ -> ('stack, _menhir_box_s) _menhir_state -> _menhir_box_s =
    fun _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s ->
      let _menhir_stack = MenhirCell1_BVAND (_menhir_stack, _menhir_s) in
      let _menhir_s = MenhirState084 in
      let _tok = _menhir_lexer _menhir_lexbuf in
      match (_tok : MenhirBasics.token) with
      | TRUE ->
          _menhir_run_021 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | STRING _v ->
          _menhir_run_022 _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s
      | PLUS ->
          _menhir_run_023 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | MINUS ->
          _menhir_run_024 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | LT ->
          _menhir_run_001 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | LPAREN ->
          _menhir_run_025 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | LNOT ->
          _menhir_run_026 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | LENGTH ->
          _menhir_run_027 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | INTTOBITVECTOR ->
          _menhir_run_029 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | INTEGER _v ->
          _menhir_run_033 _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s
      | FALSE ->
          _menhir_run_034 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | CASE ->
          _menhir_run_035 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | BVNOT ->
          _menhir_run_041 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | BITS _v ->
          _menhir_run_042 _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s
      | _ ->
          _eRR ()
  
  and _menhir_goto_semantic_constraint : type  ttv_stack. ttv_stack -> _ -> _ -> _ -> (ttv_stack, _menhir_box_s) _menhir_state -> _menhir_box_s =
    fun _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s ->
      let _tok = _menhir_lexer _menhir_lexbuf in
      match (_tok : MenhirBasics.token) with
      | TRUE ->
          let _menhir_stack = MenhirCell1_semantic_constraint (_menhir_stack, _menhir_s, _v) in
          _menhir_run_021 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState111
      | STRING _v_0 ->
          let _menhir_stack = MenhirCell1_semantic_constraint (_menhir_stack, _menhir_s, _v) in
          _menhir_run_022 _menhir_stack _menhir_lexbuf _menhir_lexer _v_0 MenhirState111
      | PLUS ->
          let _menhir_stack = MenhirCell1_semantic_constraint (_menhir_stack, _menhir_s, _v) in
          _menhir_run_023 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState111
      | MINUS ->
          let _menhir_stack = MenhirCell1_semantic_constraint (_menhir_stack, _menhir_s, _v) in
          _menhir_run_024 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState111
      | LT ->
          let _menhir_stack = MenhirCell1_semantic_constraint (_menhir_stack, _menhir_s, _v) in
          _menhir_run_001 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState111
      | LPAREN ->
          let _menhir_stack = MenhirCell1_semantic_constraint (_menhir_stack, _menhir_s, _v) in
          _menhir_run_025 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState111
      | LNOT ->
          let _menhir_stack = MenhirCell1_semantic_constraint (_menhir_stack, _menhir_s, _v) in
          _menhir_run_026 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState111
      | LENGTH ->
          let _menhir_stack = MenhirCell1_semantic_constraint (_menhir_stack, _menhir_s, _v) in
          _menhir_run_027 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState111
      | INTTOBITVECTOR ->
          let _menhir_stack = MenhirCell1_semantic_constraint (_menhir_stack, _menhir_s, _v) in
          _menhir_run_029 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState111
      | INTEGER _v_1 ->
          let _menhir_stack = MenhirCell1_semantic_constraint (_menhir_stack, _menhir_s, _v) in
          _menhir_run_033 _menhir_stack _menhir_lexbuf _menhir_lexer _v_1 MenhirState111
      | FALSE ->
          let _menhir_stack = MenhirCell1_semantic_constraint (_menhir_stack, _menhir_s, _v) in
          _menhir_run_034 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState111
      | CASE ->
          let _menhir_stack = MenhirCell1_semantic_constraint (_menhir_stack, _menhir_s, _v) in
          _menhir_run_035 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState111
      | BVNOT ->
          let _menhir_stack = MenhirCell1_semantic_constraint (_menhir_stack, _menhir_s, _v) in
          _menhir_run_041 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState111
      | BITS _v_2 ->
          let _menhir_stack = MenhirCell1_semantic_constraint (_menhir_stack, _menhir_s, _v) in
          _menhir_run_042 _menhir_stack _menhir_lexbuf _menhir_lexer _v_2 MenhirState111
      | RCURLY ->
          let sc = _v in
          let _v = _menhir_action_64 sc in
          _menhir_goto_semantic_constraint_list _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s
      | _ ->
          _eRR ()
  
  and _menhir_goto_semantic_constraint_list : type  ttv_stack. ttv_stack -> _ -> _ -> _ -> (ttv_stack, _menhir_box_s) _menhir_state -> _menhir_box_s =
    fun _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s ->
      match _menhir_s with
      | MenhirState111 ->
          _menhir_run_112 _menhir_stack _menhir_lexbuf _menhir_lexer _v
      | MenhirState020 ->
          _menhir_run_108 _menhir_stack _menhir_lexbuf _menhir_lexer _v
      | _ ->
          _menhir_fail ()
  
  and _menhir_run_112 : type  ttv_stack. (ttv_stack, _menhir_box_s) _menhir_cell1_semantic_constraint -> _ -> _ -> _ -> _menhir_box_s =
    fun _menhir_stack _menhir_lexbuf _menhir_lexer _v ->
      let MenhirCell1_semantic_constraint (_menhir_stack, _menhir_s, sc) = _menhir_stack in
      let scs = _v in
      let _v = _menhir_action_65 sc scs in
      _menhir_goto_semantic_constraint_list _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s
  
  and _menhir_run_108 : type  ttv_stack. (ttv_stack, _menhir_box_s) _menhir_cell1_LCURLY -> _ -> _ -> _ -> _menhir_box_s =
    fun _menhir_stack _menhir_lexbuf _menhir_lexer _v ->
      let _tok = _menhir_lexer _menhir_lexbuf in
      let MenhirCell1_LCURLY (_menhir_stack, _menhir_s) = _menhir_stack in
      let scs = _v in
      let _v = _menhir_action_66 scs in
      let x = _v in
      let _v = _menhir_action_59 x in
      _menhir_goto_option_semantic_constraints_ _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s _tok
  
  and _menhir_goto_option_semantic_constraints_ : type  ttv_stack. ttv_stack -> _ -> _ -> _ -> (ttv_stack, _menhir_box_s) _menhir_state -> _ -> _menhir_box_s =
    fun _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s _tok ->
      match _menhir_s with
      | MenhirState130 ->
          _menhir_run_131 _menhir_stack _menhir_lexbuf _menhir_lexer _v _tok
      | MenhirState019 ->
          _menhir_run_118 _menhir_stack _menhir_lexbuf _menhir_lexer _v _tok
      | _ ->
          _menhir_fail ()
  
  and _menhir_run_131 : type  ttv_stack. (ttv_stack, _menhir_box_s) _menhir_cell1_nonempty_list_grammar_element_ -> _ -> _ -> _ -> _ -> _menhir_box_s =
    fun _menhir_stack _menhir_lexbuf _menhir_lexer _v _tok ->
      let MenhirCell1_nonempty_list_grammar_element_ (_menhir_stack, _menhir_s, ges) = _menhir_stack in
      let scs = _v in
      let _v = _menhir_action_60 ges scs in
      match (_tok : MenhirBasics.token) with
      | OPTION ->
          let _menhir_stack = MenhirCell1_rhs (_menhir_stack, _menhir_s, _v) in
          let _menhir_s = MenhirState127 in
          let _tok = _menhir_lexer _menhir_lexbuf in
          (match (_tok : MenhirBasics.token) with
          | LT ->
              _menhir_run_001 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
          | ID _v ->
              _menhir_run_121 _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s
          | _ ->
              _eRR ())
      | SEMICOLON ->
          let x = _v in
          let _v = _menhir_action_67 x in
          _menhir_goto_separated_nonempty_list_OPTION_rhs_ _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s
      | _ ->
          _eRR ()
  
  and _menhir_goto_separated_nonempty_list_OPTION_rhs_ : type  ttv_stack. ttv_stack -> _ -> _ -> _ -> (ttv_stack, _menhir_box_s) _menhir_state -> _menhir_box_s =
    fun _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s ->
      match _menhir_s with
      | MenhirState127 ->
          _menhir_run_128 _menhir_stack _menhir_lexbuf _menhir_lexer _v
      | MenhirState120 ->
          _menhir_run_124 _menhir_stack _menhir_lexbuf _menhir_lexer _v
      | _ ->
          _menhir_fail ()
  
  and _menhir_run_128 : type  ttv_stack. (ttv_stack, _menhir_box_s) _menhir_cell1_rhs -> _ -> _ -> _ -> _menhir_box_s =
    fun _menhir_stack _menhir_lexbuf _menhir_lexer _v ->
      let MenhirCell1_rhs (_menhir_stack, _menhir_s, x) = _menhir_stack in
      let xs = _v in
      let _v = _menhir_action_68 x xs in
      _menhir_goto_separated_nonempty_list_OPTION_rhs_ _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s
  
  and _menhir_run_124 : type  ttv_stack. (ttv_stack, _menhir_box_s) _menhir_cell1_nonterminal -> _ -> _ -> _ -> _menhir_box_s =
    fun _menhir_stack _menhir_lexbuf _menhir_lexer _v ->
      let _tok = _menhir_lexer _menhir_lexbuf in
      let MenhirCell1_nonterminal (_menhir_stack, _menhir_s, nt) = _menhir_stack in
      let rhss = _v in
      let _v = _menhir_action_04 nt rhss in
      _menhir_goto_element _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s _tok
  
  and _menhir_goto_element : type  ttv_stack. ttv_stack -> _ -> _ -> _ -> (ttv_stack, _menhir_box_s) _menhir_state -> _ -> _menhir_box_s =
    fun _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s _tok ->
      let _menhir_stack = MenhirCell1_element (_menhir_stack, _menhir_s, _v) in
      match (_tok : MenhirBasics.token) with
      | LT ->
          _menhir_run_001 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState136
      | EOF ->
          let _v_0 = _menhir_action_49 () in
          _menhir_run_137 _menhir_stack _v_0
      | _ ->
          _eRR ()
  
  and _menhir_run_118 : type  ttv_stack. (ttv_stack, _menhir_box_s) _menhir_cell1_nonterminal _menhir_cell0_il_type -> _ -> _ -> _ -> _ -> _menhir_box_s =
    fun _menhir_stack _menhir_lexbuf _menhir_lexer _v _tok ->
      match (_tok : MenhirBasics.token) with
      | SEMICOLON ->
          let _tok = _menhir_lexer _menhir_lexbuf in
          let MenhirCell0_il_type (_menhir_stack, t) = _menhir_stack in
          let MenhirCell1_nonterminal (_menhir_stack, _menhir_s, nt) = _menhir_stack in
          let scs = _v in
          let _v = _menhir_action_03 nt scs t in
          _menhir_goto_element _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s _tok
      | _ ->
          _eRR ()
  
  and _menhir_run_115 : type  ttv_stack. ((ttv_stack, _menhir_box_s) _menhir_cell1_nonterminal as 'stack) -> _ -> _ -> _ -> ('stack, _menhir_box_s) _menhir_state -> _ -> _menhir_box_s =
    fun _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s _tok ->
      match (_tok : MenhirBasics.token) with
      | TIMES ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_054 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState115
      | PLUS ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_056 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState115
      | MINUS ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_060 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState115
      | LXOR ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_062 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState115
      | LTE ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_064 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState115
      | LT ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_066 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState115
      | LOR ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_086 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState115
      | LIMPLIES ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_088 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState115
      | LAND ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_068 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState115
      | GTE ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_070 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState115
      | GT ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_072 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState115
      | EQ ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_074 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState115
      | DIV ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_058 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState115
      | BVXOR ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_090 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState115
      | BVOR ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_092 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState115
      | BVLTE ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_076 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState115
      | BVLT ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_078 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState115
      | BVGTE ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_080 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState115
      | BVGT ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_082 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState115
      | BVAND ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_084 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState115
      | SEMICOLON ->
          let MenhirCell1_nonterminal (_menhir_stack, _menhir_s, nt) = _menhir_stack in
          let e = _v in
          let _v = _menhir_action_62 e nt in
          _menhir_goto_semantic_constraint _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s
      | _ ->
          _eRR ()
  
  and _menhir_run_107 : type  ttv_stack. ((ttv_stack, _menhir_box_s) _menhir_cell1_PLUS as 'stack) -> _ -> _ -> _ -> ('stack, _menhir_box_s) _menhir_state -> _ -> _menhir_box_s =
    fun _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s _tok ->
      match (_tok : MenhirBasics.token) with
      | TIMES ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_054 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState107
      | DIV ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_058 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState107
      | BVAND | BVGT | BVGTE | BVLT | BVLTE | BVOR | BVXOR | EQ | GT | GTE | LAND | LIMPLIES | LOR | LT | LTE | LXOR | MINUS | OPTION | PLUS | RPAREN | SEMICOLON ->
          let MenhirCell1_PLUS (_menhir_stack, _menhir_s) = _menhir_stack in
          let e = _v in
          let _v = _menhir_action_26 e in
          _menhir_goto_expr _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s _tok
      | _ ->
          _eRR ()
  
  and _menhir_run_106 : type  ttv_stack. ((ttv_stack, _menhir_box_s) _menhir_cell1_MINUS as 'stack) -> _ -> _ -> _ -> ('stack, _menhir_box_s) _menhir_state -> _ -> _menhir_box_s =
    fun _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s _tok ->
      match (_tok : MenhirBasics.token) with
      | TIMES ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_054 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState106
      | DIV ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_058 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState106
      | BVAND | BVGT | BVGTE | BVLT | BVLTE | BVOR | BVXOR | EQ | GT | GTE | LAND | LIMPLIES | LOR | LT | LTE | LXOR | MINUS | OPTION | PLUS | RPAREN | SEMICOLON ->
          let MenhirCell1_MINUS (_menhir_stack, _menhir_s) = _menhir_stack in
          let e = _v in
          let _v = _menhir_action_27 e in
          _menhir_goto_expr _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s _tok
      | _ ->
          _eRR ()
  
  and _menhir_run_104 : type  ttv_stack. ((ttv_stack, _menhir_box_s) _menhir_cell1_LPAREN as 'stack) -> _ -> _ -> _ -> ('stack, _menhir_box_s) _menhir_state -> _ -> _menhir_box_s =
    fun _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s _tok ->
      match (_tok : MenhirBasics.token) with
      | TIMES ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_054 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState104
      | RPAREN ->
          let _tok = _menhir_lexer _menhir_lexbuf in
          let MenhirCell1_LPAREN (_menhir_stack, _menhir_s) = _menhir_stack in
          let e = _v in
          let _v = _menhir_action_39 e in
          _menhir_goto_expr _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s _tok
      | PLUS ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_056 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState104
      | MINUS ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_060 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState104
      | LXOR ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_062 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState104
      | LTE ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_064 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState104
      | LT ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_066 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState104
      | LOR ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_086 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState104
      | LIMPLIES ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_088 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState104
      | LAND ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_068 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState104
      | GTE ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_070 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState104
      | GT ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_072 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState104
      | EQ ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_074 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState104
      | DIV ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_058 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState104
      | BVXOR ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_090 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState104
      | BVOR ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_092 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState104
      | BVLTE ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_076 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState104
      | BVLT ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_078 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState104
      | BVGTE ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_080 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState104
      | BVGT ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_082 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState104
      | BVAND ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_084 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState104
      | _ ->
          _eRR ()
  
  and _menhir_run_100 : type  ttv_stack. (ttv_stack, _menhir_box_s) _menhir_cell1_LNOT -> _ -> _ -> _ -> _ -> _menhir_box_s =
    fun _menhir_stack _menhir_lexbuf _menhir_lexer _v _tok ->
      let MenhirCell1_LNOT (_menhir_stack, _menhir_s) = _menhir_stack in
      let e = _v in
      let _v = _menhir_action_28 e in
      _menhir_goto_expr _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s _tok
  
  and _menhir_run_098 : type  ttv_stack. ((ttv_stack, _menhir_box_s) _menhir_cell1_LENGTH as 'stack) -> _ -> _ -> _ -> ('stack, _menhir_box_s) _menhir_state -> _ -> _menhir_box_s =
    fun _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s _tok ->
      match (_tok : MenhirBasics.token) with
      | TIMES ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_054 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState098
      | RPAREN ->
          let _tok = _menhir_lexer _menhir_lexbuf in
          let MenhirCell1_LENGTH (_menhir_stack, _menhir_s) = _menhir_stack in
          let e = _v in
          let _v = _menhir_action_36 e in
          _menhir_goto_expr _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s _tok
      | PLUS ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_056 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState098
      | MINUS ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_060 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState098
      | LXOR ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_062 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState098
      | LTE ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_064 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState098
      | LT ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_066 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState098
      | LOR ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_086 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState098
      | LIMPLIES ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_088 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState098
      | LAND ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_068 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState098
      | GTE ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_070 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState098
      | GT ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_072 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState098
      | EQ ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_074 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState098
      | DIV ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_058 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState098
      | BVXOR ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_090 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState098
      | BVOR ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_092 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState098
      | BVLTE ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_076 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState098
      | BVLT ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_078 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState098
      | BVGTE ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_080 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState098
      | BVGT ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_082 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState098
      | BVAND ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_084 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState098
      | _ ->
          _eRR ()
  
  and _menhir_run_096 : type  ttv_stack. ((ttv_stack, _menhir_box_s) _menhir_cell1_INTTOBITVECTOR _menhir_cell0_INTEGER as 'stack) -> _ -> _ -> _ -> ('stack, _menhir_box_s) _menhir_state -> _ -> _menhir_box_s =
    fun _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s _tok ->
      match (_tok : MenhirBasics.token) with
      | TIMES ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_054 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState096
      | RPAREN ->
          let _tok = _menhir_lexer _menhir_lexbuf in
          let MenhirCell0_INTEGER (_menhir_stack, width) = _menhir_stack in
          let MenhirCell1_INTTOBITVECTOR (_menhir_stack, _menhir_s) = _menhir_stack in
          let e = _v in
          let _v = _menhir_action_35 e width in
          _menhir_goto_expr _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s _tok
      | PLUS ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_056 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState096
      | MINUS ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_060 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState096
      | LXOR ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_062 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState096
      | LTE ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_064 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState096
      | LT ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_066 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState096
      | LOR ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_086 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState096
      | LIMPLIES ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_088 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState096
      | LAND ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_068 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState096
      | GTE ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_070 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState096
      | GT ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_072 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState096
      | EQ ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_074 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState096
      | DIV ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_058 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState096
      | BVXOR ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_090 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState096
      | BVOR ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_092 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState096
      | BVLTE ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_076 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState096
      | BVLT ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_078 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState096
      | BVGTE ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_080 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState096
      | BVGT ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_082 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState096
      | BVAND ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_084 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState096
      | _ ->
          _eRR ()
  
  and _menhir_run_093 : type  ttv_stack. (((ttv_stack, _menhir_box_s) _menhir_cell1_expr, _menhir_box_s) _menhir_cell1_BVOR as 'stack) -> _ -> _ -> _ -> ('stack, _menhir_box_s) _menhir_state -> _ -> _menhir_box_s =
    fun _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s _tok ->
      match (_tok : MenhirBasics.token) with
      | TIMES ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_054 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState093
      | PLUS ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_056 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState093
      | MINUS ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_060 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState093
      | LTE ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_064 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState093
      | LT ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_066 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState093
      | LAND ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_068 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState093
      | GTE ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_070 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState093
      | GT ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_072 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState093
      | EQ ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_074 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState093
      | DIV ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_058 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState093
      | BVLTE ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_076 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState093
      | BVLT ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_078 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState093
      | BVGTE ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_080 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState093
      | BVGT ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_082 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState093
      | BVAND ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_084 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState093
      | BVOR | BVXOR | LIMPLIES | LOR | LXOR | OPTION | RPAREN | SEMICOLON ->
          let MenhirCell1_BVOR (_menhir_stack, _) = _menhir_stack in
          let MenhirCell1_expr (_menhir_stack, _menhir_s, e1) = _menhir_stack in
          let e2 = _v in
          let _v = _menhir_action_14 e1 e2 in
          _menhir_goto_expr _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s _tok
      | _ ->
          _eRR ()
  
  and _menhir_run_091 : type  ttv_stack. (((ttv_stack, _menhir_box_s) _menhir_cell1_expr, _menhir_box_s) _menhir_cell1_BVXOR as 'stack) -> _ -> _ -> _ -> ('stack, _menhir_box_s) _menhir_state -> _ -> _menhir_box_s =
    fun _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s _tok ->
      match (_tok : MenhirBasics.token) with
      | TIMES ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_054 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState091
      | PLUS ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_056 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState091
      | MINUS ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_060 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState091
      | LTE ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_064 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState091
      | LT ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_066 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState091
      | LAND ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_068 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState091
      | GTE ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_070 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState091
      | GT ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_072 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState091
      | EQ ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_074 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState091
      | DIV ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_058 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState091
      | BVLTE ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_076 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState091
      | BVLT ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_078 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState091
      | BVGTE ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_080 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState091
      | BVGT ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_082 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState091
      | BVAND ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_084 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState091
      | BVOR | BVXOR | LIMPLIES | LOR | LXOR | OPTION | RPAREN | SEMICOLON ->
          let MenhirCell1_BVXOR (_menhir_stack, _) = _menhir_stack in
          let MenhirCell1_expr (_menhir_stack, _menhir_s, e1) = _menhir_stack in
          let e2 = _v in
          let _v = _menhir_action_15 e1 e2 in
          _menhir_goto_expr _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s _tok
      | _ ->
          _eRR ()
  
  and _menhir_run_089 : type  ttv_stack. (((ttv_stack, _menhir_box_s) _menhir_cell1_expr, _menhir_box_s) _menhir_cell1_LIMPLIES as 'stack) -> _ -> _ -> _ -> ('stack, _menhir_box_s) _menhir_state -> _ -> _menhir_box_s =
    fun _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s _tok ->
      match (_tok : MenhirBasics.token) with
      | TIMES ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_054 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState089
      | PLUS ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_056 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState089
      | MINUS ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_060 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState089
      | LXOR ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_062 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState089
      | LTE ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_064 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState089
      | LT ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_066 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState089
      | LOR ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_086 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState089
      | LIMPLIES ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_088 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState089
      | LAND ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_068 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState089
      | GTE ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_070 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState089
      | GT ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_072 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState089
      | EQ ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_074 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState089
      | DIV ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_058 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState089
      | BVXOR ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_090 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState089
      | BVOR ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_092 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState089
      | BVLTE ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_076 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState089
      | BVLT ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_078 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState089
      | BVGTE ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_080 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState089
      | BVGT ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_082 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState089
      | BVAND ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_084 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState089
      | OPTION | RPAREN | SEMICOLON ->
          let MenhirCell1_LIMPLIES (_menhir_stack, _) = _menhir_stack in
          let MenhirCell1_expr (_menhir_stack, _menhir_s, e1) = _menhir_stack in
          let e2 = _v in
          let _v = _menhir_action_08 e1 e2 in
          _menhir_goto_expr _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s _tok
      | _ ->
          _eRR ()
  
  and _menhir_run_087 : type  ttv_stack. (((ttv_stack, _menhir_box_s) _menhir_cell1_expr, _menhir_box_s) _menhir_cell1_LOR as 'stack) -> _ -> _ -> _ -> ('stack, _menhir_box_s) _menhir_state -> _ -> _menhir_box_s =
    fun _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s _tok ->
      match (_tok : MenhirBasics.token) with
      | TIMES ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_054 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState087
      | PLUS ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_056 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState087
      | MINUS ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_060 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState087
      | LTE ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_064 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState087
      | LT ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_066 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState087
      | LAND ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_068 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState087
      | GTE ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_070 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState087
      | GT ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_072 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState087
      | EQ ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_074 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState087
      | DIV ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_058 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState087
      | BVLTE ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_076 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState087
      | BVLT ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_078 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState087
      | BVGTE ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_080 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState087
      | BVGT ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_082 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState087
      | BVAND ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_084 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState087
      | BVOR | BVXOR | LIMPLIES | LOR | LXOR | OPTION | RPAREN | SEMICOLON ->
          let MenhirCell1_LOR (_menhir_stack, _) = _menhir_stack in
          let MenhirCell1_expr (_menhir_stack, _menhir_s, e1) = _menhir_stack in
          let e2 = _v in
          let _v = _menhir_action_06 e1 e2 in
          _menhir_goto_expr _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s _tok
      | _ ->
          _eRR ()
  
  and _menhir_run_085 : type  ttv_stack. (((ttv_stack, _menhir_box_s) _menhir_cell1_expr, _menhir_box_s) _menhir_cell1_BVAND as 'stack) -> _ -> _ -> _ -> ('stack, _menhir_box_s) _menhir_state -> _ -> _menhir_box_s =
    fun _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s _tok ->
      match (_tok : MenhirBasics.token) with
      | TIMES ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_054 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState085
      | PLUS ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_056 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState085
      | MINUS ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_060 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState085
      | LTE ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_064 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState085
      | LT ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_066 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState085
      | GTE ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_070 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState085
      | GT ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_072 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState085
      | EQ ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_074 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState085
      | DIV ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_058 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState085
      | BVLTE ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_076 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState085
      | BVLT ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_078 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState085
      | BVGTE ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_080 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState085
      | BVGT ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_082 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState085
      | BVAND | BVOR | BVXOR | LAND | LIMPLIES | LOR | LXOR | OPTION | RPAREN | SEMICOLON ->
          let MenhirCell1_BVAND (_menhir_stack, _) = _menhir_stack in
          let MenhirCell1_expr (_menhir_stack, _menhir_s, e1) = _menhir_stack in
          let e2 = _v in
          let _v = _menhir_action_13 e1 e2 in
          _menhir_goto_expr _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s _tok
      | _ ->
          _eRR ()
  
  and _menhir_run_083 : type  ttv_stack. (((ttv_stack, _menhir_box_s) _menhir_cell1_expr, _menhir_box_s) _menhir_cell1_BVGT as 'stack) -> _ -> _ -> _ -> ('stack, _menhir_box_s) _menhir_state -> _ -> _menhir_box_s =
    fun _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s _tok ->
      match (_tok : MenhirBasics.token) with
      | TIMES ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_054 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState083
      | PLUS ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_056 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState083
      | MINUS ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_060 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState083
      | DIV ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_058 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState083
      | BVAND | BVGT | BVGTE | BVLT | BVLTE | BVOR | BVXOR | EQ | GT | GTE | LAND | LIMPLIES | LOR | LT | LTE | LXOR | OPTION | RPAREN | SEMICOLON ->
          let MenhirCell1_BVGT (_menhir_stack, _) = _menhir_stack in
          let MenhirCell1_expr (_menhir_stack, _menhir_s, e1) = _menhir_stack in
          let e2 = _v in
          let _v = _menhir_action_23 e1 e2 in
          _menhir_goto_expr _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s _tok
      | _ ->
          _eRR ()
  
  and _menhir_run_081 : type  ttv_stack. (((ttv_stack, _menhir_box_s) _menhir_cell1_expr, _menhir_box_s) _menhir_cell1_BVGTE as 'stack) -> _ -> _ -> _ -> ('stack, _menhir_box_s) _menhir_state -> _ -> _menhir_box_s =
    fun _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s _tok ->
      match (_tok : MenhirBasics.token) with
      | TIMES ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_054 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState081
      | PLUS ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_056 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState081
      | MINUS ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_060 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState081
      | DIV ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_058 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState081
      | BVAND | BVGT | BVGTE | BVLT | BVLTE | BVOR | BVXOR | EQ | GT | GTE | LAND | LIMPLIES | LOR | LT | LTE | LXOR | OPTION | RPAREN | SEMICOLON ->
          let MenhirCell1_BVGTE (_menhir_stack, _) = _menhir_stack in
          let MenhirCell1_expr (_menhir_stack, _menhir_s, e1) = _menhir_stack in
          let e2 = _v in
          let _v = _menhir_action_24 e1 e2 in
          _menhir_goto_expr _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s _tok
      | _ ->
          _eRR ()
  
  and _menhir_run_079 : type  ttv_stack. (((ttv_stack, _menhir_box_s) _menhir_cell1_expr, _menhir_box_s) _menhir_cell1_BVLT as 'stack) -> _ -> _ -> _ -> ('stack, _menhir_box_s) _menhir_state -> _ -> _menhir_box_s =
    fun _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s _tok ->
      match (_tok : MenhirBasics.token) with
      | TIMES ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_054 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState079
      | PLUS ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_056 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState079
      | MINUS ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_060 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState079
      | DIV ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_058 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState079
      | BVAND | BVGT | BVGTE | BVLT | BVLTE | BVOR | BVXOR | EQ | GT | GTE | LAND | LIMPLIES | LOR | LT | LTE | LXOR | OPTION | RPAREN | SEMICOLON ->
          let MenhirCell1_BVLT (_menhir_stack, _) = _menhir_stack in
          let MenhirCell1_expr (_menhir_stack, _menhir_s, e1) = _menhir_stack in
          let e2 = _v in
          let _v = _menhir_action_21 e1 e2 in
          _menhir_goto_expr _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s _tok
      | _ ->
          _eRR ()
  
  and _menhir_run_077 : type  ttv_stack. (((ttv_stack, _menhir_box_s) _menhir_cell1_expr, _menhir_box_s) _menhir_cell1_BVLTE as 'stack) -> _ -> _ -> _ -> ('stack, _menhir_box_s) _menhir_state -> _ -> _menhir_box_s =
    fun _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s _tok ->
      match (_tok : MenhirBasics.token) with
      | TIMES ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_054 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState077
      | PLUS ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_056 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState077
      | MINUS ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_060 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState077
      | DIV ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_058 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState077
      | BVAND | BVGT | BVGTE | BVLT | BVLTE | BVOR | BVXOR | EQ | GT | GTE | LAND | LIMPLIES | LOR | LT | LTE | LXOR | OPTION | RPAREN | SEMICOLON ->
          let MenhirCell1_BVLTE (_menhir_stack, _) = _menhir_stack in
          let MenhirCell1_expr (_menhir_stack, _menhir_s, e1) = _menhir_stack in
          let e2 = _v in
          let _v = _menhir_action_22 e1 e2 in
          _menhir_goto_expr _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s _tok
      | _ ->
          _eRR ()
  
  and _menhir_run_075 : type  ttv_stack. (((ttv_stack, _menhir_box_s) _menhir_cell1_expr, _menhir_box_s) _menhir_cell1_EQ as 'stack) -> _ -> _ -> _ -> ('stack, _menhir_box_s) _menhir_state -> _ -> _menhir_box_s =
    fun _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s _tok ->
      match (_tok : MenhirBasics.token) with
      | TIMES ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_054 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState075
      | PLUS ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_056 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState075
      | MINUS ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_060 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState075
      | DIV ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_058 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState075
      | BVAND | BVGT | BVGTE | BVLT | BVLTE | BVOR | BVXOR | EQ | GT | GTE | LAND | LIMPLIES | LOR | LT | LTE | LXOR | OPTION | RPAREN | SEMICOLON ->
          let MenhirCell1_EQ (_menhir_stack, _) = _menhir_stack in
          let MenhirCell1_expr (_menhir_stack, _menhir_s, e1) = _menhir_stack in
          let e2 = _v in
          let _v = _menhir_action_20 e1 e2 in
          _menhir_goto_expr _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s _tok
      | _ ->
          _eRR ()
  
  and _menhir_run_073 : type  ttv_stack. (((ttv_stack, _menhir_box_s) _menhir_cell1_expr, _menhir_box_s) _menhir_cell1_GT as 'stack) -> _ -> _ -> _ -> ('stack, _menhir_box_s) _menhir_state -> _ -> _menhir_box_s =
    fun _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s _tok ->
      match (_tok : MenhirBasics.token) with
      | TIMES ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_054 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState073
      | PLUS ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_056 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState073
      | MINUS ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_060 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState073
      | DIV ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_058 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState073
      | BVAND | BVGT | BVGTE | BVLT | BVLTE | BVOR | BVXOR | EQ | GT | GTE | LAND | LIMPLIES | LOR | LT | LTE | LXOR | OPTION | RPAREN | SEMICOLON ->
          let MenhirCell1_GT (_menhir_stack, _) = _menhir_stack in
          let MenhirCell1_expr (_menhir_stack, _menhir_s, e1) = _menhir_stack in
          let e2 = _v in
          let _v = _menhir_action_18 e1 e2 in
          _menhir_goto_expr _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s _tok
      | _ ->
          _eRR ()
  
  and _menhir_run_071 : type  ttv_stack. (((ttv_stack, _menhir_box_s) _menhir_cell1_expr, _menhir_box_s) _menhir_cell1_GTE as 'stack) -> _ -> _ -> _ -> ('stack, _menhir_box_s) _menhir_state -> _ -> _menhir_box_s =
    fun _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s _tok ->
      match (_tok : MenhirBasics.token) with
      | TIMES ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_054 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState071
      | PLUS ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_056 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState071
      | MINUS ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_060 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState071
      | DIV ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_058 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState071
      | BVAND | BVGT | BVGTE | BVLT | BVLTE | BVOR | BVXOR | EQ | GT | GTE | LAND | LIMPLIES | LOR | LT | LTE | LXOR | OPTION | RPAREN | SEMICOLON ->
          let MenhirCell1_GTE (_menhir_stack, _) = _menhir_stack in
          let MenhirCell1_expr (_menhir_stack, _menhir_s, e1) = _menhir_stack in
          let e2 = _v in
          let _v = _menhir_action_19 e1 e2 in
          _menhir_goto_expr _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s _tok
      | _ ->
          _eRR ()
  
  and _menhir_run_069 : type  ttv_stack. (((ttv_stack, _menhir_box_s) _menhir_cell1_expr, _menhir_box_s) _menhir_cell1_LAND as 'stack) -> _ -> _ -> _ -> ('stack, _menhir_box_s) _menhir_state -> _ -> _menhir_box_s =
    fun _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s _tok ->
      match (_tok : MenhirBasics.token) with
      | TIMES ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_054 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState069
      | PLUS ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_056 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState069
      | MINUS ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_060 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState069
      | LTE ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_064 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState069
      | LT ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_066 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState069
      | GTE ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_070 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState069
      | GT ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_072 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState069
      | EQ ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_074 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState069
      | DIV ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_058 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState069
      | BVLTE ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_076 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState069
      | BVLT ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_078 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState069
      | BVGTE ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_080 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState069
      | BVGT ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_082 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState069
      | BVAND | BVOR | BVXOR | LAND | LIMPLIES | LOR | LXOR | OPTION | RPAREN | SEMICOLON ->
          let MenhirCell1_LAND (_menhir_stack, _) = _menhir_stack in
          let MenhirCell1_expr (_menhir_stack, _menhir_s, e1) = _menhir_stack in
          let e2 = _v in
          let _v = _menhir_action_05 e1 e2 in
          _menhir_goto_expr _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s _tok
      | _ ->
          _eRR ()
  
  and _menhir_run_067 : type  ttv_stack. (((ttv_stack, _menhir_box_s) _menhir_cell1_expr, _menhir_box_s) _menhir_cell1_LT as 'stack) -> _ -> _ -> _ -> ('stack, _menhir_box_s) _menhir_state -> _ -> _menhir_box_s =
    fun _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s _tok ->
      match (_tok : MenhirBasics.token) with
      | TIMES ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_054 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState067
      | PLUS ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_056 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState067
      | MINUS ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_060 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState067
      | DIV ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_058 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState067
      | BVAND | BVGT | BVGTE | BVLT | BVLTE | BVOR | BVXOR | EQ | GT | GTE | LAND | LIMPLIES | LOR | LT | LTE | LXOR | OPTION | RPAREN | SEMICOLON ->
          let MenhirCell1_LT (_menhir_stack, _) = _menhir_stack in
          let MenhirCell1_expr (_menhir_stack, _menhir_s, e1) = _menhir_stack in
          let e2 = _v in
          let _v = _menhir_action_16 e1 e2 in
          _menhir_goto_expr _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s _tok
      | _ ->
          _eRR ()
  
  and _menhir_run_065 : type  ttv_stack. (((ttv_stack, _menhir_box_s) _menhir_cell1_expr, _menhir_box_s) _menhir_cell1_LTE as 'stack) -> _ -> _ -> _ -> ('stack, _menhir_box_s) _menhir_state -> _ -> _menhir_box_s =
    fun _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s _tok ->
      match (_tok : MenhirBasics.token) with
      | TIMES ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_054 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState065
      | PLUS ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_056 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState065
      | MINUS ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_060 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState065
      | DIV ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_058 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState065
      | BVAND | BVGT | BVGTE | BVLT | BVLTE | BVOR | BVXOR | EQ | GT | GTE | LAND | LIMPLIES | LOR | LT | LTE | LXOR | OPTION | RPAREN | SEMICOLON ->
          let MenhirCell1_LTE (_menhir_stack, _) = _menhir_stack in
          let MenhirCell1_expr (_menhir_stack, _menhir_s, e1) = _menhir_stack in
          let e2 = _v in
          let _v = _menhir_action_17 e1 e2 in
          _menhir_goto_expr _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s _tok
      | _ ->
          _eRR ()
  
  and _menhir_run_063 : type  ttv_stack. (((ttv_stack, _menhir_box_s) _menhir_cell1_expr, _menhir_box_s) _menhir_cell1_LXOR as 'stack) -> _ -> _ -> _ -> ('stack, _menhir_box_s) _menhir_state -> _ -> _menhir_box_s =
    fun _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s _tok ->
      match (_tok : MenhirBasics.token) with
      | TIMES ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_054 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState063
      | PLUS ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_056 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState063
      | MINUS ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_060 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState063
      | LTE ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_064 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState063
      | LT ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_066 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState063
      | LAND ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_068 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState063
      | GTE ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_070 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState063
      | GT ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_072 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState063
      | EQ ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_074 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState063
      | DIV ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_058 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState063
      | BVLTE ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_076 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState063
      | BVLT ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_078 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState063
      | BVGTE ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_080 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState063
      | BVGT ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_082 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState063
      | BVAND ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_084 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState063
      | BVOR | BVXOR | LIMPLIES | LOR | LXOR | OPTION | RPAREN | SEMICOLON ->
          let MenhirCell1_LXOR (_menhir_stack, _) = _menhir_stack in
          let MenhirCell1_expr (_menhir_stack, _menhir_s, e1) = _menhir_stack in
          let e2 = _v in
          let _v = _menhir_action_07 e1 e2 in
          _menhir_goto_expr _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s _tok
      | _ ->
          _eRR ()
  
  and _menhir_run_061 : type  ttv_stack. (((ttv_stack, _menhir_box_s) _menhir_cell1_expr, _menhir_box_s) _menhir_cell1_MINUS as 'stack) -> _ -> _ -> _ -> ('stack, _menhir_box_s) _menhir_state -> _ -> _menhir_box_s =
    fun _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s _tok ->
      match (_tok : MenhirBasics.token) with
      | TIMES ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_054 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState061
      | DIV ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_058 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState061
      | BVAND | BVGT | BVGTE | BVLT | BVLTE | BVOR | BVXOR | EQ | GT | GTE | LAND | LIMPLIES | LOR | LT | LTE | LXOR | MINUS | OPTION | PLUS | RPAREN | SEMICOLON ->
          let MenhirCell1_MINUS (_menhir_stack, _) = _menhir_stack in
          let MenhirCell1_expr (_menhir_stack, _menhir_s, e1) = _menhir_stack in
          let e2 = _v in
          let _v = _menhir_action_10 e1 e2 in
          _menhir_goto_expr _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s _tok
      | _ ->
          _eRR ()
  
  and _menhir_run_059 : type  ttv_stack. ((ttv_stack, _menhir_box_s) _menhir_cell1_expr, _menhir_box_s) _menhir_cell1_DIV -> _ -> _ -> _ -> _ -> _menhir_box_s =
    fun _menhir_stack _menhir_lexbuf _menhir_lexer _v _tok ->
      let MenhirCell1_DIV (_menhir_stack, _) = _menhir_stack in
      let MenhirCell1_expr (_menhir_stack, _menhir_s, e1) = _menhir_stack in
      let e2 = _v in
      let _v = _menhir_action_12 e1 e2 in
      _menhir_goto_expr _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s _tok
  
  and _menhir_run_057 : type  ttv_stack. (((ttv_stack, _menhir_box_s) _menhir_cell1_expr, _menhir_box_s) _menhir_cell1_PLUS as 'stack) -> _ -> _ -> _ -> ('stack, _menhir_box_s) _menhir_state -> _ -> _menhir_box_s =
    fun _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s _tok ->
      match (_tok : MenhirBasics.token) with
      | TIMES ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_054 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState057
      | DIV ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_058 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState057
      | BVAND | BVGT | BVGTE | BVLT | BVLTE | BVOR | BVXOR | EQ | GT | GTE | LAND | LIMPLIES | LOR | LT | LTE | LXOR | MINUS | OPTION | PLUS | RPAREN | SEMICOLON ->
          let MenhirCell1_PLUS (_menhir_stack, _) = _menhir_stack in
          let MenhirCell1_expr (_menhir_stack, _menhir_s, e1) = _menhir_stack in
          let e2 = _v in
          let _v = _menhir_action_09 e1 e2 in
          _menhir_goto_expr _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s _tok
      | _ ->
          _eRR ()
  
  and _menhir_run_055 : type  ttv_stack. ((ttv_stack, _menhir_box_s) _menhir_cell1_expr, _menhir_box_s) _menhir_cell1_TIMES -> _ -> _ -> _ -> _ -> _menhir_box_s =
    fun _menhir_stack _menhir_lexbuf _menhir_lexer _v _tok ->
      let MenhirCell1_TIMES (_menhir_stack, _) = _menhir_stack in
      let MenhirCell1_expr (_menhir_stack, _menhir_s, e1) = _menhir_stack in
      let e2 = _v in
      let _v = _menhir_action_11 e1 e2 in
      _menhir_goto_expr _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s _tok
  
  and _menhir_run_053 : type  ttv_stack. (((ttv_stack, _menhir_box_s) _menhir_cell1_OPTION, _menhir_box_s) _menhir_cell1_nt_expr as 'stack) -> _ -> _ -> _ -> ('stack, _menhir_box_s) _menhir_state -> _ -> _menhir_box_s =
    fun _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s _tok ->
      match (_tok : MenhirBasics.token) with
      | TIMES ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_054 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState053
      | PLUS ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_056 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState053
      | MINUS ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_060 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState053
      | LXOR ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_062 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState053
      | LTE ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_064 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState053
      | LT ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_066 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState053
      | LOR ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_086 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState053
      | LIMPLIES ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_088 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState053
      | LAND ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_068 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState053
      | GTE ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_070 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState053
      | GT ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_072 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState053
      | EQ ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_074 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState053
      | DIV ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_058 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState053
      | BVXOR ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_090 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState053
      | BVOR ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_092 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState053
      | BVLTE ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_076 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState053
      | BVLT ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_078 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState053
      | BVGTE ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_080 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState053
      | BVGT ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_082 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState053
      | BVAND ->
          let _menhir_stack = MenhirCell1_expr (_menhir_stack, _menhir_s, _v) in
          _menhir_run_084 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState053
      | OPTION | RPAREN | SEMICOLON ->
          let MenhirCell1_nt_expr (_menhir_stack, _, e1) = _menhir_stack in
          let MenhirCell1_OPTION (_menhir_stack, _menhir_s) = _menhir_stack in
          let e2 = _v in
          let _v = _menhir_action_01 e1 e2 in
          _menhir_goto_case_list _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s _tok
      | _ ->
          _eRR ()
  
  and _menhir_goto_case_list : type  ttv_stack. ttv_stack -> _ -> _ -> _ -> (ttv_stack, _menhir_box_s) _menhir_state -> _ -> _menhir_box_s =
    fun _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s _tok ->
      match _menhir_s with
      | MenhirState037 ->
          _menhir_run_095 _menhir_stack _menhir_lexbuf _menhir_lexer _v _tok
      | MenhirState053 ->
          _menhir_run_094 _menhir_stack _menhir_lexbuf _menhir_lexer _v _tok
      | _ ->
          _menhir_fail ()
  
  and _menhir_run_095 : type  ttv_stack. ((ttv_stack, _menhir_box_s) _menhir_cell1_CASE, _menhir_box_s) _menhir_cell1_nt_expr -> _ -> _ -> _ -> _ -> _menhir_box_s =
    fun _menhir_stack _menhir_lexbuf _menhir_lexer _v _tok ->
      let MenhirCell1_nt_expr (_menhir_stack, _, e) = _menhir_stack in
      let MenhirCell1_CASE (_menhir_stack, _menhir_s) = _menhir_stack in
      let cs = _v in
      let _v = _menhir_action_37 cs e in
      _menhir_goto_expr _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s _tok
  
  and _menhir_run_094 : type  ttv_stack. (((ttv_stack, _menhir_box_s) _menhir_cell1_OPTION, _menhir_box_s) _menhir_cell1_nt_expr, _menhir_box_s) _menhir_cell1_expr -> _ -> _ -> _ -> _ -> _menhir_box_s =
    fun _menhir_stack _menhir_lexbuf _menhir_lexer _v _tok ->
      let MenhirCell1_expr (_menhir_stack, _, e2) = _menhir_stack in
      let MenhirCell1_nt_expr (_menhir_stack, _, e1) = _menhir_stack in
      let MenhirCell1_OPTION (_menhir_stack, _menhir_s) = _menhir_stack in
      let cs = _v in
      let _v = _menhir_action_02 cs e1 e2 in
      _menhir_goto_case_list _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s _tok
  
  and _menhir_run_052 : type  ttv_stack. (ttv_stack, _menhir_box_s) _menhir_cell1_BVNOT -> _ -> _ -> _ -> _ -> _menhir_box_s =
    fun _menhir_stack _menhir_lexbuf _menhir_lexer _v _tok ->
      let MenhirCell1_BVNOT (_menhir_stack, _menhir_s) = _menhir_stack in
      let e = _v in
      let _v = _menhir_action_25 e in
      _menhir_goto_expr _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s _tok
  
  and _menhir_run_123 : type  ttv_stack. (ttv_stack, _menhir_box_s) _menhir_cell1_ID -> _ -> _ -> _ -> _ -> _menhir_box_s =
    fun _menhir_stack _menhir_lexbuf _menhir_lexer _v _tok ->
      let MenhirCell1_ID (_menhir_stack, _menhir_s, i) = _menhir_stack in
      let nt = _v in
      let _v = _menhir_action_41 i nt in
      _menhir_goto_grammar_element _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s _tok
  
  and _menhir_run_113 : type  ttv_stack. ttv_stack -> _ -> _ -> _ -> (ttv_stack, _menhir_box_s) _menhir_state -> _ -> _menhir_box_s =
    fun _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s _tok ->
      match (_tok : MenhirBasics.token) with
      | DOT ->
          let _menhir_stack = MenhirCell1_nonterminal (_menhir_stack, _menhir_s, _v) in
          _menhir_run_050 _menhir_stack _menhir_lexbuf _menhir_lexer
      | ASSIGN ->
          let _menhir_stack = MenhirCell1_nonterminal (_menhir_stack, _menhir_s, _v) in
          let _menhir_s = MenhirState114 in
          let _tok = _menhir_lexer _menhir_lexbuf in
          (match (_tok : MenhirBasics.token) with
          | TRUE ->
              _menhir_run_021 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
          | STRING _v ->
              _menhir_run_022 _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s
          | PLUS ->
              _menhir_run_023 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
          | MINUS ->
              _menhir_run_024 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
          | LT ->
              _menhir_run_001 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
          | LPAREN ->
              _menhir_run_025 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
          | LNOT ->
              _menhir_run_026 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
          | LENGTH ->
              _menhir_run_027 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
          | INTTOBITVECTOR ->
              _menhir_run_029 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
          | INTEGER _v ->
              _menhir_run_033 _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s
          | FALSE ->
              _menhir_run_034 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
          | CASE ->
              _menhir_run_035 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
          | BVNOT ->
              _menhir_run_041 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
          | BITS _v ->
              _menhir_run_042 _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s
          | _ ->
              _eRR ())
      | BVAND | BVGT | BVGTE | BVLT | BVLTE | BVOR | BVXOR | DIV | EQ | GT | GTE | LAND | LIMPLIES | LOR | LPAREN | LT | LTE | LXOR | MINUS | PLUS | SEMICOLON | TIMES ->
          let nt = _v in
          let _v = _menhir_action_54 nt in
          _menhir_goto_nt_expr _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s _tok
      | _ ->
          _eRR ()
  
  and _menhir_run_050 : type  ttv_stack. (ttv_stack, _menhir_box_s) _menhir_cell1_nonterminal -> _ -> _ -> _menhir_box_s =
    fun _menhir_stack _menhir_lexbuf _menhir_lexer ->
      let _menhir_s = MenhirState050 in
      let _tok = _menhir_lexer _menhir_lexbuf in
      match (_tok : MenhirBasics.token) with
      | LT ->
          _menhir_run_001 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
      | _ ->
          _eRR ()
  
  and _menhir_goto_nt_expr : type  ttv_stack. ttv_stack -> _ -> _ -> _ -> (ttv_stack, _menhir_box_s) _menhir_state -> _ -> _menhir_box_s =
    fun _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s _tok ->
      match _menhir_s with
      | MenhirState050 ->
          _menhir_run_051 _menhir_stack _menhir_lexbuf _menhir_lexer _v _tok
      | MenhirState020 ->
          _menhir_run_043 _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s _tok
      | MenhirState114 ->
          _menhir_run_043 _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s _tok
      | MenhirState111 ->
          _menhir_run_043 _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s _tok
      | MenhirState023 ->
          _menhir_run_043 _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s _tok
      | MenhirState024 ->
          _menhir_run_043 _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s _tok
      | MenhirState025 ->
          _menhir_run_043 _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s _tok
      | MenhirState026 ->
          _menhir_run_043 _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s _tok
      | MenhirState028 ->
          _menhir_run_043 _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s _tok
      | MenhirState032 ->
          _menhir_run_043 _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s _tok
      | MenhirState092 ->
          _menhir_run_043 _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s _tok
      | MenhirState090 ->
          _menhir_run_043 _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s _tok
      | MenhirState088 ->
          _menhir_run_043 _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s _tok
      | MenhirState086 ->
          _menhir_run_043 _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s _tok
      | MenhirState084 ->
          _menhir_run_043 _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s _tok
      | MenhirState082 ->
          _menhir_run_043 _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s _tok
      | MenhirState080 ->
          _menhir_run_043 _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s _tok
      | MenhirState078 ->
          _menhir_run_043 _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s _tok
      | MenhirState076 ->
          _menhir_run_043 _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s _tok
      | MenhirState074 ->
          _menhir_run_043 _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s _tok
      | MenhirState072 ->
          _menhir_run_043 _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s _tok
      | MenhirState070 ->
          _menhir_run_043 _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s _tok
      | MenhirState068 ->
          _menhir_run_043 _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s _tok
      | MenhirState066 ->
          _menhir_run_043 _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s _tok
      | MenhirState064 ->
          _menhir_run_043 _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s _tok
      | MenhirState062 ->
          _menhir_run_043 _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s _tok
      | MenhirState060 ->
          _menhir_run_043 _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s _tok
      | MenhirState058 ->
          _menhir_run_043 _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s _tok
      | MenhirState056 ->
          _menhir_run_043 _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s _tok
      | MenhirState054 ->
          _menhir_run_043 _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s _tok
      | MenhirState040 ->
          _menhir_run_043 _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s _tok
      | MenhirState041 ->
          _menhir_run_043 _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s _tok
      | MenhirState038 ->
          _menhir_run_039 _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s _tok
      | MenhirState035 ->
          _menhir_run_036 _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s _tok
      | _ ->
          _menhir_fail ()
  
  and _menhir_run_051 : type  ttv_stack. (ttv_stack, _menhir_box_s) _menhir_cell1_nonterminal -> _ -> _ -> _ -> _ -> _menhir_box_s =
    fun _menhir_stack _menhir_lexbuf _menhir_lexer _v _tok ->
      let MenhirCell1_nonterminal (_menhir_stack, _menhir_s, nt) = _menhir_stack in
      let nts = _v in
      let _v = _menhir_action_55 nt nts in
      _menhir_goto_nt_expr _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s _tok
  
  and _menhir_run_043 : type  ttv_stack. ttv_stack -> _ -> _ -> _ -> (ttv_stack, _menhir_box_s) _menhir_state -> _ -> _menhir_box_s =
    fun _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s _tok ->
      let _menhir_stack = MenhirCell1_nt_expr (_menhir_stack, _menhir_s, _v) in
      match (_tok : MenhirBasics.token) with
      | LPAREN ->
          let _tok = _menhir_lexer _menhir_lexbuf in
          (match (_tok : MenhirBasics.token) with
          | INTEGER _v_0 ->
              let _tok = _menhir_lexer _menhir_lexbuf in
              (match (_tok : MenhirBasics.token) with
              | RPAREN ->
                  let _tok = _menhir_lexer _menhir_lexbuf in
                  let index = _v_0 in
                  let _v = _menhir_action_48 index in
                  let x = _v in
                  let _v = _menhir_action_57 x in
                  _menhir_goto_option_index_ _menhir_stack _menhir_lexbuf _menhir_lexer _v _tok
              | _ ->
                  _eRR ())
          | _ ->
              _eRR ())
      | BVAND | BVGT | BVGTE | BVLT | BVLTE | BVOR | BVXOR | DIV | EQ | GT | GTE | LAND | LIMPLIES | LOR | LT | LTE | LXOR | MINUS | OPTION | PLUS | RPAREN | SEMICOLON | TIMES ->
          let _v = _menhir_action_56 () in
          _menhir_goto_option_index_ _menhir_stack _menhir_lexbuf _menhir_lexer _v _tok
      | _ ->
          _eRR ()
  
  and _menhir_goto_option_index_ : type  ttv_stack. (ttv_stack, _menhir_box_s) _menhir_cell1_nt_expr -> _ -> _ -> _ -> _ -> _menhir_box_s =
    fun _menhir_stack _menhir_lexbuf _menhir_lexer _v _tok ->
      let MenhirCell1_nt_expr (_menhir_stack, _menhir_s, e) = _menhir_stack in
      let index = _v in
      let _v = _menhir_action_38 e index in
      _menhir_goto_expr _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s _tok
  
  and _menhir_run_039 : type  ttv_stack. ((ttv_stack, _menhir_box_s) _menhir_cell1_OPTION as 'stack) -> _ -> _ -> _ -> ('stack, _menhir_box_s) _menhir_state -> _ -> _menhir_box_s =
    fun _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s _tok ->
      let _menhir_stack = MenhirCell1_nt_expr (_menhir_stack, _menhir_s, _v) in
      match (_tok : MenhirBasics.token) with
      | ARROW ->
          let _menhir_s = MenhirState040 in
          let _tok = _menhir_lexer _menhir_lexbuf in
          (match (_tok : MenhirBasics.token) with
          | TRUE ->
              _menhir_run_021 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
          | STRING _v ->
              _menhir_run_022 _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s
          | PLUS ->
              _menhir_run_023 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
          | MINUS ->
              _menhir_run_024 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
          | LT ->
              _menhir_run_001 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
          | LPAREN ->
              _menhir_run_025 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
          | LNOT ->
              _menhir_run_026 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
          | LENGTH ->
              _menhir_run_027 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
          | INTTOBITVECTOR ->
              _menhir_run_029 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
          | INTEGER _v ->
              _menhir_run_033 _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s
          | FALSE ->
              _menhir_run_034 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
          | CASE ->
              _menhir_run_035 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
          | BVNOT ->
              _menhir_run_041 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
          | BITS _v ->
              _menhir_run_042 _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s
          | _ ->
              _eRR ())
      | _ ->
          _eRR ()
  
  and _menhir_run_036 : type  ttv_stack. ((ttv_stack, _menhir_box_s) _menhir_cell1_CASE as 'stack) -> _ -> _ -> _ -> ('stack, _menhir_box_s) _menhir_state -> _ -> _menhir_box_s =
    fun _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s _tok ->
      let _menhir_stack = MenhirCell1_nt_expr (_menhir_stack, _menhir_s, _v) in
      match (_tok : MenhirBasics.token) with
      | OF ->
          let _menhir_s = MenhirState037 in
          let _tok = _menhir_lexer _menhir_lexbuf in
          (match (_tok : MenhirBasics.token) with
          | OPTION ->
              let _menhir_stack = MenhirCell1_OPTION (_menhir_stack, _menhir_s) in
              let _menhir_s = MenhirState038 in
              let _tok = _menhir_lexer _menhir_lexbuf in
              (match (_tok : MenhirBasics.token) with
              | LT ->
                  _menhir_run_001 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
              | _ ->
                  _eRR ())
          | _ ->
              _eRR ())
      | _ ->
          _eRR ()
  
  and _menhir_run_049 : type  ttv_stack. ttv_stack -> _ -> _ -> _ -> (ttv_stack, _menhir_box_s) _menhir_state -> _ -> _menhir_box_s =
    fun _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s _tok ->
      match (_tok : MenhirBasics.token) with
      | DOT ->
          let _menhir_stack = MenhirCell1_nonterminal (_menhir_stack, _menhir_s, _v) in
          _menhir_run_050 _menhir_stack _menhir_lexbuf _menhir_lexer
      | ARROW | BVAND | BVGT | BVGTE | BVLT | BVLTE | BVOR | BVXOR | DIV | EQ | GT | GTE | LAND | LIMPLIES | LOR | LPAREN | LT | LTE | LXOR | MINUS | OF | OPTION | PLUS | RPAREN | SEMICOLON | TIMES ->
          let nt = _v in
          let _v = _menhir_action_54 nt in
          _menhir_goto_nt_expr _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s _tok
      | _ ->
          _eRR ()
  
  and _menhir_run_005 : type  ttv_stack. ttv_stack -> _ -> _ -> _ -> (ttv_stack, _menhir_box_s) _menhir_state -> _ -> _menhir_box_s =
    fun _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s _tok ->
      let _menhir_stack = MenhirCell1_nonterminal (_menhir_stack, _menhir_s, _v) in
      match (_tok : MenhirBasics.token) with
      | TYPEANNOT ->
          let _tok = _menhir_lexer _menhir_lexbuf in
          (match (_tok : MenhirBasics.token) with
          | STR ->
              let _tok = _menhir_lexer _menhir_lexbuf in
              let _v = _menhir_action_44 () in
              _menhir_goto_il_type _menhir_stack _menhir_lexbuf _menhir_lexer _v _tok
          | MACHINEINT ->
              let _tok = _menhir_lexer _menhir_lexbuf in
              (match (_tok : MenhirBasics.token) with
              | LPAREN ->
                  let _tok = _menhir_lexer _menhir_lexbuf in
                  (match (_tok : MenhirBasics.token) with
                  | INTEGER _v_1 ->
                      let _tok = _menhir_lexer _menhir_lexbuf in
                      (match (_tok : MenhirBasics.token) with
                      | RPAREN ->
                          let _tok = _menhir_lexer _menhir_lexbuf in
                          let width = _v_1 in
                          let _v = _menhir_action_47 width in
                          _menhir_goto_il_type _menhir_stack _menhir_lexbuf _menhir_lexer _v _tok
                      | _ ->
                          _eRR ())
                  | _ ->
                      _eRR ())
              | _ ->
                  _eRR ())
          | INT ->
              let _tok = _menhir_lexer _menhir_lexbuf in
              let _v = _menhir_action_43 () in
              _menhir_goto_il_type _menhir_stack _menhir_lexbuf _menhir_lexer _v _tok
          | BOOL ->
              let _tok = _menhir_lexer _menhir_lexbuf in
              let _v = _menhir_action_42 () in
              _menhir_goto_il_type _menhir_stack _menhir_lexbuf _menhir_lexer _v _tok
          | BITVECTOR ->
              let _tok = _menhir_lexer _menhir_lexbuf in
              (match (_tok : MenhirBasics.token) with
              | LPAREN ->
                  let _tok = _menhir_lexer _menhir_lexbuf in
                  (match (_tok : MenhirBasics.token) with
                  | INTEGER _v_5 ->
                      let _tok = _menhir_lexer _menhir_lexbuf in
                      (match (_tok : MenhirBasics.token) with
                      | RPAREN ->
                          let _tok = _menhir_lexer _menhir_lexbuf in
                          let len = _v_5 in
                          let _v = _menhir_action_45 len in
                          _menhir_goto_il_type _menhir_stack _menhir_lexbuf _menhir_lexer _v _tok
                      | _ ->
                          _eRR ())
                  | _ ->
                      _eRR ())
              | _ ->
                  _eRR ())
          | BITLIST ->
              let _tok = _menhir_lexer _menhir_lexbuf in
              let _v = _menhir_action_46 () in
              _menhir_goto_il_type _menhir_stack _menhir_lexbuf _menhir_lexer _v _tok
          | _ ->
              _eRR ())
      | PRODUCTION ->
          let _menhir_s = MenhirState120 in
          let _tok = _menhir_lexer _menhir_lexbuf in
          (match (_tok : MenhirBasics.token) with
          | LT ->
              _menhir_run_001 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
          | ID _v ->
              _menhir_run_121 _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s
          | _ ->
              _eRR ())
      | _ ->
          _eRR ()
  
  and _menhir_goto_il_type : type  ttv_stack. (ttv_stack, _menhir_box_s) _menhir_cell1_nonterminal -> _ -> _ -> _ -> _ -> _menhir_box_s =
    fun _menhir_stack _menhir_lexbuf _menhir_lexer _v _tok ->
      let _menhir_stack = MenhirCell0_il_type (_menhir_stack, _v) in
      match (_tok : MenhirBasics.token) with
      | LCURLY ->
          _menhir_run_020 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState019
      | SEMICOLON ->
          let _v_0 = _menhir_action_58 () in
          _menhir_run_118 _menhir_stack _menhir_lexbuf _menhir_lexer _v_0 _tok
      | _ ->
          _eRR ()
  
  let _menhir_run_000 : type  ttv_stack. ttv_stack -> _ -> _ -> _menhir_box_s =
    fun _menhir_stack _menhir_lexbuf _menhir_lexer ->
      let _tok = _menhir_lexer _menhir_lexbuf in
      match (_tok : MenhirBasics.token) with
      | LT ->
          _menhir_run_001 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState000
      | EOF ->
          let _v = _menhir_action_49 () in
          _menhir_run_134 _menhir_stack _v
      | _ ->
          _eRR ()
  
end

let s =
  fun _menhir_lexer _menhir_lexbuf ->
    let _menhir_stack = () in
    let MenhirBox_s v = _menhir_run_000 _menhir_stack _menhir_lexbuf _menhir_lexer in
    v
