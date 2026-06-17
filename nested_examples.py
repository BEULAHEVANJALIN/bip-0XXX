from tree import parse_forest, print_tree
import secrets
from reference import *
from nested_musig2_exec import *

def example1():
    root = parse_forest("Alice(Bob,Carol),Dave", root_name="Abby")
    print("Nested musig 2 example as per paper")
    print_tree(root)
    msg = secrets.token_bytes(32)

    # Setup
    key_gen_tree(root)

    aggx = get_xonly_pk(root.keyagg_ctx)
    print("Round 1 starts")
    round1(root, aggx, msg)

    print("Round 2 starts")
    round2(root, [root.out_internal], [], msg)


    assert(schnorr_verify(msg, get_xonly_pk(root.keyagg_ctx), root.state_ + root.out_))

example1()