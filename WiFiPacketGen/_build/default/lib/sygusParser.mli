
(* The type of tokens. *)

type token = 
  | UNIT
  | UNDERSCORE
  | TRUE
  | TOP
  | STR
  | SEQ
  | RPAREN
  | PLUSPLUS
  | LPAREN
  | INTEGER of (int)
  | INT
  | ID of (string)
  | HYPHEN
  | FUN
  | FALSE
  | EOF
  | EMPTY
  | DOT
  | DEFINE
  | CAPSEQ
  | BOOL
  | BITVEC
  | BITS of (bool list)
  | AS

(* This exception is raised by the monolithic API functions. *)

exception Error

(* The monolithic API. *)

val s: (Lexing.lexbuf -> token) -> Lexing.lexbuf -> (SygusAst.sygus_ast)
