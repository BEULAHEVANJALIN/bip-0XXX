from tree import *
import secrets
from reference import *
from nested_musig2_exec import *

def example1():
    root = parse_forest("A(D,E),B(F,G)", root_name="Abby")
    print("Nested musig 2 example as per paper")
    msg = secrets.token_bytes(32)

    # Setup
    key_gen_tree(root)
    print_tree(root)

    aggx = get_xonly_pk(root.keyagg_ctx)
    print("Round 1 starts")
    round1(root, aggx, msg)

    print("Round 2 starts")
    round2(root, [], [], msg)

    R = root.state_
    if verify_r(R, root):
        print("R computed success")
    else:
        print("R computation failed")

    assert(schnorr_verify(msg, get_xonly_pk(root.keyagg_ctx), root.state_ + root.out_))

def verify_r(R: bytes, node: Node):
    if node.is_leaf():
        if R != node.state_:
            print(node.value + " failed to verify R")
            print(node.state_.hex().upper())
            return False
        else:
            return True
    else:
        for w in node.children:
            if not verify_r(R, w):
                return False
        return True

example1()