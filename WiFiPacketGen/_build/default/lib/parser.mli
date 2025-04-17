
(* The type of tokens. *)

type token = 
  | TYPEANNOT
  | TRUE
  | TIMES
  | STRING of (string)
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
  | INTEGER of (int)
  | INT
  | ID of (string)
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
  | BITS of (bool list)
  | BITLIST
  | ASSIGN
  | ARROW

(* This exception is raised by the monolithic API functions. *)

exception Error

(* The monolithic API. *)

val s: (Lexing.lexbuf -> token) -> Lexing.lexbuf -> (Ast.ast)
