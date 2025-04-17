
module MenhirBasics = struct
  
  exception Error
  
  let _eRR =
    fun _s ->
      raise Error
  
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
    | INTEGER of (
# 28 "lib/sygusParser.mly"
      (int)
# 24 "lib/sygusParser.ml"
  )
    | INT
    | ID of (
# 27 "lib/sygusParser.mly"
      (string)
# 30 "lib/sygusParser.ml"
  )
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
    | BITS of (
# 26 "lib/sygusParser.mly"
      (bool list)
# 45 "lib/sygusParser.ml"
  )
    | AS
  
end

include MenhirBasics

# 1 "lib/sygusParser.mly"
  
open SygusAst

# 57 "lib/sygusParser.ml"

type ('s, 'r) _menhir_state = 
  | MenhirState20 : ('s _menhir_cell0_top_type, _menhir_box_s) _menhir_state
    (** State 20.
        Stack shape : top_type.
        Start symbol: s. *)

  | MenhirState24 : (('s, _menhir_box_s) _menhir_cell1_LPAREN, _menhir_box_s) _menhir_state
    (** State 24.
        Stack shape : LPAREN.
        Start symbol: s. *)

  | MenhirState33 : (('s, _menhir_box_s) _menhir_cell1_LPAREN, _menhir_box_s) _menhir_state
    (** State 33.
        Stack shape : LPAREN.
        Start symbol: s. *)

  | MenhirState36 : (('s, _menhir_box_s) _menhir_cell1_bit_list, _menhir_box_s) _menhir_state
    (** State 36.
        Stack shape : bit_list.
        Start symbol: s. *)

  | MenhirState49 : (('s, _menhir_box_s) _menhir_cell1_LPAREN _menhir_cell0_ID, _menhir_box_s) _menhir_state
    (** State 49.
        Stack shape : LPAREN ID.
        Start symbol: s. *)

  | MenhirState55 : (('s, _menhir_box_s) _menhir_cell1_lisp_term, _menhir_box_s) _menhir_state
    (** State 55.
        Stack shape : lisp_term.
        Start symbol: s. *)


and ('s, 'r) _menhir_cell1_bit_list = 
  | MenhirCell1_bit_list of 's * ('s, 'r) _menhir_state * (bool list)

and ('s, 'r) _menhir_cell1_lisp_term = 
  | MenhirCell1_lisp_term of 's * ('s, 'r) _menhir_state * (SygusAst.sygus_ast)

and 's _menhir_cell0_top_type = 
  | MenhirCell0_top_type of 's * (unit)

and 's _menhir_cell0_ID = 
  | MenhirCell0_ID of 's * (
# 27 "lib/sygusParser.mly"
      (string)
# 104 "lib/sygusParser.ml"
)

and ('s, 'r) _menhir_cell1_LPAREN = 
  | MenhirCell1_LPAREN of 's * ('s, 'r) _menhir_state

and _menhir_box_s = 
  | MenhirBox_s of (SygusAst.sygus_ast) [@@unboxed]

let _menhir_action_01 =
  fun () ->
    (
# 66 "lib/sygusParser.mly"
  ( [] )
# 118 "lib/sygusParser.ml"
     : (bool list))

let _menhir_action_02 =
  fun b ->
    (
# 68 "lib/sygusParser.mly"
  ( [b] )
# 126 "lib/sygusParser.ml"
     : (bool list))

let _menhir_action_03 =
  fun bls ->
    (
# 70 "lib/sygusParser.mly"
  ( List.flatten bls )
# 134 "lib/sygusParser.ml"
     : (bool list))

let _menhir_action_04 =
  fun bls ->
    (
# 72 "lib/sygusParser.mly"
( List.flatten bls )
# 142 "lib/sygusParser.ml"
     : (bool list))

let _menhir_action_05 =
  fun () ->
    (
# 76 "lib/sygusParser.mly"
       ( true )
# 150 "lib/sygusParser.ml"
     : (bool))

let _menhir_action_06 =
  fun () ->
    (
# 77 "lib/sygusParser.mly"
        ( false )
# 158 "lib/sygusParser.ml"
     : (bool))

let _menhir_action_07 =
  fun () ->
    (
# 47 "lib/sygusParser.mly"
       ()
# 166 "lib/sygusParser.ml"
     : (unit))

let _menhir_action_08 =
  fun () ->
    (
# 48 "lib/sygusParser.mly"
        ()
# 174 "lib/sygusParser.ml"
     : (unit))

let _menhir_action_09 =
  fun () ->
    (
# 49 "lib/sygusParser.mly"
                                ()
# 182 "lib/sygusParser.ml"
     : (unit))

let _menhir_action_10 =
  fun () ->
    (
# 50 "lib/sygusParser.mly"
                                               ()
# 190 "lib/sygusParser.ml"
     : (unit))

let _menhir_action_11 =
  fun id ts ->
    (
# 54 "lib/sygusParser.mly"
  ( Node (id, ts) )
# 198 "lib/sygusParser.ml"
     : (SygusAst.sygus_ast))

let _menhir_action_12 =
  fun bits ->
    (
# 56 "lib/sygusParser.mly"
  ( BVLeaf (List.length bits, bits) )
# 206 "lib/sygusParser.ml"
     : (SygusAst.sygus_ast))

let _menhir_action_13 =
  fun id ->
    (
# 58 "lib/sygusParser.mly"
  ( VarLeaf id )
# 214 "lib/sygusParser.ml"
     : (SygusAst.sygus_ast))

let _menhir_action_14 =
  fun bits ->
    (
# 60 "lib/sygusParser.mly"
  ( BLLeaf bits )
# 222 "lib/sygusParser.ml"
     : (SygusAst.sygus_ast))

let _menhir_action_15 =
  fun i ->
    (
# 62 "lib/sygusParser.mly"
  ( IntLeaf i )
# 230 "lib/sygusParser.ml"
     : (SygusAst.sygus_ast))

let _menhir_action_16 =
  fun () ->
    (
# 216 "<standard.mly>"
    ( [] )
# 238 "lib/sygusParser.ml"
     : (SygusAst.sygus_ast list))

let _menhir_action_17 =
  fun x xs ->
    (
# 219 "<standard.mly>"
    ( x :: xs )
# 246 "lib/sygusParser.ml"
     : (SygusAst.sygus_ast list))

let _menhir_action_18 =
  fun x ->
    (
# 228 "<standard.mly>"
    ( [ x ] )
# 254 "lib/sygusParser.ml"
     : (bool list list))

let _menhir_action_19 =
  fun x xs ->
    (
# 231 "<standard.mly>"
    ( x :: xs )
# 262 "lib/sygusParser.ml"
     : (bool list list))

let _menhir_action_20 =
  fun d ->
    (
# 36 "lib/sygusParser.mly"
                       ( d )
# 270 "lib/sygusParser.ml"
     : (SygusAst.sygus_ast))

let _menhir_action_21 =
  fun t ->
    (
# 40 "lib/sygusParser.mly"
  ( t )
# 278 "lib/sygusParser.ml"
     : (SygusAst.sygus_ast))

let _menhir_action_22 =
  fun () ->
    (
# 43 "lib/sygusParser.mly"
      ()
# 286 "lib/sygusParser.ml"
     : (unit))

let _menhir_action_23 =
  fun () ->
    (
# 44 "lib/sygusParser.mly"
         ()
# 294 "lib/sygusParser.ml"
     : (unit))

let _menhir_print_token : token -> string =
  fun _tok ->
    match _tok with
    | AS ->
        "AS"
    | BITS _ ->
        "BITS"
    | BITVEC ->
        "BITVEC"
    | BOOL ->
        "BOOL"
    | CAPSEQ ->
        "CAPSEQ"
    | DEFINE ->
        "DEFINE"
    | DOT ->
        "DOT"
    | EMPTY ->
        "EMPTY"
    | EOF ->
        "EOF"
    | FALSE ->
        "FALSE"
    | FUN ->
        "FUN"
    | HYPHEN ->
        "HYPHEN"
    | ID _ ->
        "ID"
    | INT ->
        "INT"
    | INTEGER _ ->
        "INTEGER"
    | LPAREN ->
        "LPAREN"
    | PLUSPLUS ->
        "PLUSPLUS"
    | RPAREN ->
        "RPAREN"
    | SEQ ->
        "SEQ"
    | STR ->
        "STR"
    | TOP ->
        "TOP"
    | TRUE ->
        "TRUE"
    | UNDERSCORE ->
        "UNDERSCORE"
    | UNIT ->
        "UNIT"

let _menhir_fail : unit -> 'a =
  fun () ->
    Printf.eprintf "Internal failure -- please contact the parser generator's developers.\n%!";
    assert false

include struct
  
  [@@@ocaml.warning "-4-37"]
  
  let _menhir_run_58 : type  ttv_stack. ttv_stack _menhir_cell0_top_type -> _ -> _ -> _ -> _ -> _menhir_box_s =
    fun _menhir_stack _menhir_lexbuf _menhir_lexer _v _tok ->
      match (_tok : MenhirBasics.token) with
      | RPAREN ->
          let _tok = _menhir_lexer _menhir_lexbuf in
          (match (_tok : MenhirBasics.token) with
          | RPAREN ->
              let _tok = _menhir_lexer _menhir_lexbuf in
              let MenhirCell0_top_type (_menhir_stack, _) = _menhir_stack in
              let t = _v in
              let _v = _menhir_action_21 t in
              (match (_tok : MenhirBasics.token) with
              | EOF ->
                  let d = _v in
                  let _v = _menhir_action_20 d in
                  MenhirBox_s _v
              | _ ->
                  _eRR ())
          | _ ->
              _eRR ())
      | _ ->
          _eRR ()
  
  let rec _menhir_run_21 : type  ttv_stack. ttv_stack -> _ -> _ -> (ttv_stack, _menhir_box_s) _menhir_state -> _menhir_box_s =
    fun _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s ->
      let _menhir_stack = MenhirCell1_LPAREN (_menhir_stack, _menhir_s) in
      let _tok = _menhir_lexer _menhir_lexbuf in
      match (_tok : MenhirBasics.token) with
      | STR ->
          _menhir_run_22 _menhir_stack _menhir_lexbuf _menhir_lexer
      | SEQ ->
          _menhir_run_26 _menhir_stack _menhir_lexbuf _menhir_lexer
      | ID _v ->
          let _menhir_stack = MenhirCell0_ID (_menhir_stack, _v) in
          let _tok = _menhir_lexer _menhir_lexbuf in
          (match (_tok : MenhirBasics.token) with
          | LPAREN ->
              _menhir_run_21 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState49
          | INTEGER _v_0 ->
              _menhir_run_50 _menhir_stack _menhir_lexbuf _menhir_lexer _v_0 MenhirState49
          | ID _v_1 ->
              _menhir_run_51 _menhir_stack _menhir_lexbuf _menhir_lexer _v_1 MenhirState49
          | BITS _v_2 ->
              _menhir_run_52 _menhir_stack _menhir_lexbuf _menhir_lexer _v_2 MenhirState49
          | RPAREN ->
              let _v_3 = _menhir_action_16 () in
              _menhir_run_53 _menhir_stack _menhir_lexbuf _menhir_lexer _v_3
          | _ ->
              _eRR ())
      | AS ->
          _menhir_run_38 _menhir_stack _menhir_lexbuf _menhir_lexer
      | _ ->
          _eRR ()
  
  and _menhir_run_22 : type  ttv_stack. (ttv_stack, _menhir_box_s) _menhir_cell1_LPAREN -> _ -> _ -> _menhir_box_s =
    fun _menhir_stack _menhir_lexbuf _menhir_lexer ->
      let _tok = _menhir_lexer _menhir_lexbuf in
      match (_tok : MenhirBasics.token) with
      | DOT ->
          let _tok = _menhir_lexer _menhir_lexbuf in
          (match (_tok : MenhirBasics.token) with
          | PLUSPLUS ->
              let _menhir_s = MenhirState24 in
              let _tok = _menhir_lexer _menhir_lexbuf in
              (match (_tok : MenhirBasics.token) with
              | LPAREN ->
                  _menhir_run_25 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
              | _ ->
                  _eRR ())
          | _ ->
              _eRR ())
      | _ ->
          _eRR ()
  
  and _menhir_run_25 : type  ttv_stack. ttv_stack -> _ -> _ -> (ttv_stack, _menhir_box_s) _menhir_state -> _menhir_box_s =
    fun _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s ->
      let _menhir_stack = MenhirCell1_LPAREN (_menhir_stack, _menhir_s) in
      let _tok = _menhir_lexer _menhir_lexbuf in
      match (_tok : MenhirBasics.token) with
      | STR ->
          _menhir_run_22 _menhir_stack _menhir_lexbuf _menhir_lexer
      | SEQ ->
          _menhir_run_26 _menhir_stack _menhir_lexbuf _menhir_lexer
      | AS ->
          _menhir_run_38 _menhir_stack _menhir_lexbuf _menhir_lexer
      | _ ->
          _eRR ()
  
  and _menhir_run_26 : type  ttv_stack. (ttv_stack, _menhir_box_s) _menhir_cell1_LPAREN -> _ -> _ -> _menhir_box_s =
    fun _menhir_stack _menhir_lexbuf _menhir_lexer ->
      let _tok = _menhir_lexer _menhir_lexbuf in
      match (_tok : MenhirBasics.token) with
      | DOT ->
          let _tok = _menhir_lexer _menhir_lexbuf in
          (match (_tok : MenhirBasics.token) with
          | UNIT ->
              let _tok = _menhir_lexer _menhir_lexbuf in
              (match (_tok : MenhirBasics.token) with
              | TRUE ->
                  let _tok = _menhir_lexer _menhir_lexbuf in
                  let _v = _menhir_action_05 () in
                  _menhir_goto_bool _menhir_stack _menhir_lexbuf _menhir_lexer _v _tok
              | FALSE ->
                  let _tok = _menhir_lexer _menhir_lexbuf in
                  let _v = _menhir_action_06 () in
                  _menhir_goto_bool _menhir_stack _menhir_lexbuf _menhir_lexer _v _tok
              | _ ->
                  _eRR ())
          | PLUSPLUS ->
              let _menhir_s = MenhirState33 in
              let _tok = _menhir_lexer _menhir_lexbuf in
              (match (_tok : MenhirBasics.token) with
              | LPAREN ->
                  _menhir_run_25 _menhir_stack _menhir_lexbuf _menhir_lexer _menhir_s
              | _ ->
                  _eRR ())
          | _ ->
              _eRR ())
      | _ ->
          _eRR ()
  
  and _menhir_goto_bool : type  ttv_stack. (ttv_stack, _menhir_box_s) _menhir_cell1_LPAREN -> _ -> _ -> _ -> _ -> _menhir_box_s =
    fun _menhir_stack _menhir_lexbuf _menhir_lexer _v _tok ->
      match (_tok : MenhirBasics.token) with
      | RPAREN ->
          let _tok = _menhir_lexer _menhir_lexbuf in
          let MenhirCell1_LPAREN (_menhir_stack, _menhir_s) = _menhir_stack in
          let b = _v in
          let _v = _menhir_action_02 b in
          _menhir_goto_bit_list _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s _tok
      | _ ->
          _eRR ()
  
  and _menhir_goto_bit_list : type  ttv_stack. ttv_stack -> _ -> _ -> _ -> (ttv_stack, _menhir_box_s) _menhir_state -> _ -> _menhir_box_s =
    fun _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s _tok ->
      match _menhir_s with
      | MenhirState20 ->
          _menhir_run_57 _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s _tok
      | MenhirState49 ->
          _menhir_run_57 _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s _tok
      | MenhirState55 ->
          _menhir_run_57 _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s _tok
      | MenhirState24 ->
          _menhir_run_36 _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s _tok
      | MenhirState36 ->
          _menhir_run_36 _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s _tok
      | MenhirState33 ->
          _menhir_run_36 _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s _tok
  
  and _menhir_run_57 : type  ttv_stack. ttv_stack -> _ -> _ -> _ -> (ttv_stack, _menhir_box_s) _menhir_state -> _ -> _menhir_box_s =
    fun _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s _tok ->
      let bits = _v in
      let _v = _menhir_action_14 bits in
      _menhir_goto_lisp_term _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s _tok
  
  and _menhir_goto_lisp_term : type  ttv_stack. ttv_stack -> _ -> _ -> _ -> (ttv_stack, _menhir_box_s) _menhir_state -> _ -> _menhir_box_s =
    fun _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s _tok ->
      match _menhir_s with
      | MenhirState20 ->
          _menhir_run_58 _menhir_stack _menhir_lexbuf _menhir_lexer _v _tok
      | MenhirState55 ->
          _menhir_run_55 _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s _tok
      | MenhirState49 ->
          _menhir_run_55 _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s _tok
      | _ ->
          _menhir_fail ()
  
  and _menhir_run_55 : type  ttv_stack. ttv_stack -> _ -> _ -> _ -> (ttv_stack, _menhir_box_s) _menhir_state -> _ -> _menhir_box_s =
    fun _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s _tok ->
      let _menhir_stack = MenhirCell1_lisp_term (_menhir_stack, _menhir_s, _v) in
      match (_tok : MenhirBasics.token) with
      | LPAREN ->
          _menhir_run_21 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState55
      | INTEGER _v_0 ->
          _menhir_run_50 _menhir_stack _menhir_lexbuf _menhir_lexer _v_0 MenhirState55
      | ID _v_1 ->
          _menhir_run_51 _menhir_stack _menhir_lexbuf _menhir_lexer _v_1 MenhirState55
      | BITS _v_2 ->
          _menhir_run_52 _menhir_stack _menhir_lexbuf _menhir_lexer _v_2 MenhirState55
      | RPAREN ->
          let _v_3 = _menhir_action_16 () in
          _menhir_run_56 _menhir_stack _menhir_lexbuf _menhir_lexer _v_3
      | _ ->
          _eRR ()
  
  and _menhir_run_50 : type  ttv_stack. ttv_stack -> _ -> _ -> _ -> (ttv_stack, _menhir_box_s) _menhir_state -> _menhir_box_s =
    fun _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s ->
      let _tok = _menhir_lexer _menhir_lexbuf in
      let i = _v in
      let _v = _menhir_action_15 i in
      _menhir_goto_lisp_term _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s _tok
  
  and _menhir_run_51 : type  ttv_stack. ttv_stack -> _ -> _ -> _ -> (ttv_stack, _menhir_box_s) _menhir_state -> _menhir_box_s =
    fun _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s ->
      let _tok = _menhir_lexer _menhir_lexbuf in
      let id = _v in
      let _v = _menhir_action_13 id in
      _menhir_goto_lisp_term _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s _tok
  
  and _menhir_run_52 : type  ttv_stack. ttv_stack -> _ -> _ -> _ -> (ttv_stack, _menhir_box_s) _menhir_state -> _menhir_box_s =
    fun _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s ->
      let _tok = _menhir_lexer _menhir_lexbuf in
      let bits = _v in
      let _v = _menhir_action_12 bits in
      _menhir_goto_lisp_term _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s _tok
  
  and _menhir_run_56 : type  ttv_stack. (ttv_stack, _menhir_box_s) _menhir_cell1_lisp_term -> _ -> _ -> _ -> _menhir_box_s =
    fun _menhir_stack _menhir_lexbuf _menhir_lexer _v ->
      let MenhirCell1_lisp_term (_menhir_stack, _menhir_s, x) = _menhir_stack in
      let xs = _v in
      let _v = _menhir_action_17 x xs in
      _menhir_goto_list_lisp_term_ _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s
  
  and _menhir_goto_list_lisp_term_ : type  ttv_stack. ttv_stack -> _ -> _ -> _ -> (ttv_stack, _menhir_box_s) _menhir_state -> _menhir_box_s =
    fun _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s ->
      match _menhir_s with
      | MenhirState55 ->
          _menhir_run_56 _menhir_stack _menhir_lexbuf _menhir_lexer _v
      | MenhirState49 ->
          _menhir_run_53 _menhir_stack _menhir_lexbuf _menhir_lexer _v
      | _ ->
          _menhir_fail ()
  
  and _menhir_run_53 : type  ttv_stack. (ttv_stack, _menhir_box_s) _menhir_cell1_LPAREN _menhir_cell0_ID -> _ -> _ -> _ -> _menhir_box_s =
    fun _menhir_stack _menhir_lexbuf _menhir_lexer _v ->
      let _tok = _menhir_lexer _menhir_lexbuf in
      let MenhirCell0_ID (_menhir_stack, id) = _menhir_stack in
      let MenhirCell1_LPAREN (_menhir_stack, _menhir_s) = _menhir_stack in
      let ts = _v in
      let _v = _menhir_action_11 id ts in
      _menhir_goto_lisp_term _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s _tok
  
  and _menhir_run_36 : type  ttv_stack. ttv_stack -> _ -> _ -> _ -> (ttv_stack, _menhir_box_s) _menhir_state -> _ -> _menhir_box_s =
    fun _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s _tok ->
      match (_tok : MenhirBasics.token) with
      | LPAREN ->
          let _menhir_stack = MenhirCell1_bit_list (_menhir_stack, _menhir_s, _v) in
          _menhir_run_25 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState36
      | RPAREN ->
          let x = _v in
          let _v = _menhir_action_18 x in
          _menhir_goto_nonempty_list_bit_list_ _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s
      | _ ->
          _eRR ()
  
  and _menhir_goto_nonempty_list_bit_list_ : type  ttv_stack. ttv_stack -> _ -> _ -> _ -> (ttv_stack, _menhir_box_s) _menhir_state -> _menhir_box_s =
    fun _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s ->
      match _menhir_s with
      | MenhirState24 ->
          _menhir_run_47 _menhir_stack _menhir_lexbuf _menhir_lexer _v
      | MenhirState36 ->
          _menhir_run_37 _menhir_stack _menhir_lexbuf _menhir_lexer _v
      | MenhirState33 ->
          _menhir_run_34 _menhir_stack _menhir_lexbuf _menhir_lexer _v
      | _ ->
          _menhir_fail ()
  
  and _menhir_run_47 : type  ttv_stack. (ttv_stack, _menhir_box_s) _menhir_cell1_LPAREN -> _ -> _ -> _ -> _menhir_box_s =
    fun _menhir_stack _menhir_lexbuf _menhir_lexer _v ->
      let _tok = _menhir_lexer _menhir_lexbuf in
      let MenhirCell1_LPAREN (_menhir_stack, _menhir_s) = _menhir_stack in
      let bls = _v in
      let _v = _menhir_action_03 bls in
      _menhir_goto_bit_list _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s _tok
  
  and _menhir_run_37 : type  ttv_stack. (ttv_stack, _menhir_box_s) _menhir_cell1_bit_list -> _ -> _ -> _ -> _menhir_box_s =
    fun _menhir_stack _menhir_lexbuf _menhir_lexer _v ->
      let MenhirCell1_bit_list (_menhir_stack, _menhir_s, x) = _menhir_stack in
      let xs = _v in
      let _v = _menhir_action_19 x xs in
      _menhir_goto_nonempty_list_bit_list_ _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s
  
  and _menhir_run_34 : type  ttv_stack. (ttv_stack, _menhir_box_s) _menhir_cell1_LPAREN -> _ -> _ -> _ -> _menhir_box_s =
    fun _menhir_stack _menhir_lexbuf _menhir_lexer _v ->
      let _tok = _menhir_lexer _menhir_lexbuf in
      let MenhirCell1_LPAREN (_menhir_stack, _menhir_s) = _menhir_stack in
      let bls = _v in
      let _v = _menhir_action_04 bls in
      _menhir_goto_bit_list _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s _tok
  
  and _menhir_run_38 : type  ttv_stack. (ttv_stack, _menhir_box_s) _menhir_cell1_LPAREN -> _ -> _ -> _menhir_box_s =
    fun _menhir_stack _menhir_lexbuf _menhir_lexer ->
      let _tok = _menhir_lexer _menhir_lexbuf in
      match (_tok : MenhirBasics.token) with
      | SEQ ->
          let _tok = _menhir_lexer _menhir_lexbuf in
          (match (_tok : MenhirBasics.token) with
          | DOT ->
              let _tok = _menhir_lexer _menhir_lexbuf in
              (match (_tok : MenhirBasics.token) with
              | EMPTY ->
                  let _tok = _menhir_lexer _menhir_lexbuf in
                  (match (_tok : MenhirBasics.token) with
                  | LPAREN ->
                      let _tok = _menhir_lexer _menhir_lexbuf in
                      (match (_tok : MenhirBasics.token) with
                      | CAPSEQ ->
                          let _tok = _menhir_lexer _menhir_lexbuf in
                          (match (_tok : MenhirBasics.token) with
                          | BOOL ->
                              let _tok = _menhir_lexer _menhir_lexbuf in
                              (match (_tok : MenhirBasics.token) with
                              | RPAREN ->
                                  let _tok = _menhir_lexer _menhir_lexbuf in
                                  (match (_tok : MenhirBasics.token) with
                                  | RPAREN ->
                                      let _tok = _menhir_lexer _menhir_lexbuf in
                                      let MenhirCell1_LPAREN (_menhir_stack, _menhir_s) = _menhir_stack in
                                      let _v = _menhir_action_01 () in
                                      _menhir_goto_bit_list _menhir_stack _menhir_lexbuf _menhir_lexer _v _menhir_s _tok
                                  | _ ->
                                      _eRR ())
                              | _ ->
                                  _eRR ())
                          | _ ->
                              _eRR ())
                      | _ ->
                          _eRR ())
                  | _ ->
                      _eRR ())
              | _ ->
                  _eRR ())
          | _ ->
              _eRR ())
      | _ ->
          _eRR ()
  
  let _menhir_goto_top_type : type  ttv_stack. ttv_stack -> _ -> _ -> _ -> _ -> _menhir_box_s =
    fun _menhir_stack _menhir_lexbuf _menhir_lexer _v _tok ->
      let _menhir_stack = MenhirCell0_top_type (_menhir_stack, _v) in
      match (_tok : MenhirBasics.token) with
      | LPAREN ->
          _menhir_run_21 _menhir_stack _menhir_lexbuf _menhir_lexer MenhirState20
      | INTEGER _v_0 ->
          _menhir_run_50 _menhir_stack _menhir_lexbuf _menhir_lexer _v_0 MenhirState20
      | ID _v_1 ->
          _menhir_run_51 _menhir_stack _menhir_lexbuf _menhir_lexer _v_1 MenhirState20
      | BITS _v_2 ->
          _menhir_run_52 _menhir_stack _menhir_lexbuf _menhir_lexer _v_2 MenhirState20
      | _ ->
          _eRR ()
  
  let _menhir_goto_il_ty : type  ttv_stack. ttv_stack -> _ -> _ -> _ -> _menhir_box_s =
    fun _menhir_stack _menhir_lexbuf _menhir_lexer _tok ->
      let _v = _menhir_action_23 () in
      _menhir_goto_top_type _menhir_stack _menhir_lexbuf _menhir_lexer _v _tok
  
  let _menhir_run_00 : type  ttv_stack. ttv_stack -> _ -> _ -> _menhir_box_s =
    fun _menhir_stack _menhir_lexbuf _menhir_lexer ->
      let _tok = _menhir_lexer _menhir_lexbuf in
      match (_tok : MenhirBasics.token) with
      | LPAREN ->
          let _tok = _menhir_lexer _menhir_lexbuf in
          (match (_tok : MenhirBasics.token) with
          | LPAREN ->
              let _tok = _menhir_lexer _menhir_lexbuf in
              (match (_tok : MenhirBasics.token) with
              | DEFINE ->
                  let _tok = _menhir_lexer _menhir_lexbuf in
                  (match (_tok : MenhirBasics.token) with
                  | HYPHEN ->
                      let _tok = _menhir_lexer _menhir_lexbuf in
                      (match (_tok : MenhirBasics.token) with
                      | FUN ->
                          let _tok = _menhir_lexer _menhir_lexbuf in
                          (match (_tok : MenhirBasics.token) with
                          | TOP ->
                              let _tok = _menhir_lexer _menhir_lexbuf in
                              (match (_tok : MenhirBasics.token) with
                              | LPAREN ->
                                  let _tok = _menhir_lexer _menhir_lexbuf in
                                  (match (_tok : MenhirBasics.token) with
                                  | RPAREN ->
                                      let _tok = _menhir_lexer _menhir_lexbuf in
                                      (match (_tok : MenhirBasics.token) with
                                      | LPAREN ->
                                          let _tok = _menhir_lexer _menhir_lexbuf in
                                          (match (_tok : MenhirBasics.token) with
                                          | UNDERSCORE ->
                                              let _tok = _menhir_lexer _menhir_lexbuf in
                                              (match (_tok : MenhirBasics.token) with
                                              | BITVEC ->
                                                  let _tok = _menhir_lexer _menhir_lexbuf in
                                                  (match (_tok : MenhirBasics.token) with
                                                  | INTEGER _ ->
                                                      let _tok = _menhir_lexer _menhir_lexbuf in
                                                      (match (_tok : MenhirBasics.token) with
                                                      | RPAREN ->
                                                          let _tok = _menhir_lexer _menhir_lexbuf in
                                                          let _ = _menhir_action_10 () in
                                                          _menhir_goto_il_ty _menhir_stack _menhir_lexbuf _menhir_lexer _tok
                                                      | _ ->
                                                          _eRR ())
                                                  | _ ->
                                                      _eRR ())
                                              | _ ->
                                                  _eRR ())
                                          | CAPSEQ ->
                                              let _tok = _menhir_lexer _menhir_lexbuf in
                                              (match (_tok : MenhirBasics.token) with
                                              | BOOL ->
                                                  let _tok = _menhir_lexer _menhir_lexbuf in
                                                  (match (_tok : MenhirBasics.token) with
                                                  | RPAREN ->
                                                      let _tok = _menhir_lexer _menhir_lexbuf in
                                                      let _ = _menhir_action_09 () in
                                                      _menhir_goto_il_ty _menhir_stack _menhir_lexbuf _menhir_lexer _tok
                                                  | _ ->
                                                      _eRR ())
                                              | _ ->
                                                  _eRR ())
                                          | _ ->
                                              _eRR ())
                                      | INT ->
                                          let _tok = _menhir_lexer _menhir_lexbuf in
                                          let _ = _menhir_action_07 () in
                                          _menhir_goto_il_ty _menhir_stack _menhir_lexbuf _menhir_lexer _tok
                                      | ID _ ->
                                          let _tok = _menhir_lexer _menhir_lexbuf in
                                          let _v = _menhir_action_22 () in
                                          _menhir_goto_top_type _menhir_stack _menhir_lexbuf _menhir_lexer _v _tok
                                      | BOOL ->
                                          let _tok = _menhir_lexer _menhir_lexbuf in
                                          let _ = _menhir_action_08 () in
                                          _menhir_goto_il_ty _menhir_stack _menhir_lexbuf _menhir_lexer _tok
                                      | _ ->
                                          _eRR ())
                                  | _ ->
                                      _eRR ())
                              | _ ->
                                  _eRR ())
                          | _ ->
                              _eRR ())
                      | _ ->
                          _eRR ())
                  | _ ->
                      _eRR ())
              | _ ->
                  _eRR ())
          | _ ->
              _eRR ())
      | _ ->
          _eRR ()
  
end

let s =
  fun _menhir_lexer _menhir_lexbuf ->
    let _menhir_stack = () in
    let MenhirBox_s v = _menhir_run_00 _menhir_stack _menhir_lexbuf _menhir_lexer in
    v
