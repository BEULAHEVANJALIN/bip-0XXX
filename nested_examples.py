from tree import *
import secrets
from reference import *
from nested_musig2_exec import *

def example1():
    root = parse_forest("A(D,E),B(F,G)", root_name="Abby")
    print("example without tweak")
    msg = secrets.token_bytes(32)

    # Setup
    key_gen_tree(root)
    print_tree(root)

    aggx = get_xonly_pk(root.keyagg_ctx)
    print("Round 1 starts")
    round1(root, aggx, msg)

    print("Round 2 starts")
    session_ctx = SessionContext([], [], [], [], msg)
    round2(root, session_ctx)

    R = root.state_
    if verify_r(R, root):
        print("R computed success")
    else:
        print("R computation failed")

    assert(schnorr_verify(msg, get_xonly_pk(root.keyagg_ctx), root.state_ + root.out_))

def tweak_example():
    root = parse_forest("A(D,E),B(F,G)", root_name="Abby")
    print("example with tweak")
    msg = secrets.token_bytes(32)

    # Setup
    key_gen_tree(root)
    print_tree(root)

    aggx = get_xonly_pk(root.keyagg_ctx)
    print("Round 1 starts")
    round1(root, aggx, msg)

    print("Round 2 starts")
    tweaks = [secrets.token_bytes(32) for _ in range(4)]
    is_xonly = [secrets.choice([False, True]) for _ in range(4)]
    session_ctx = SessionContext(
        nonce_path=[],
        pk_tree=[],
        tweaks = tweaks,
        is_xonly = is_xonly,
        msg=msg,
    )
    round2(root, session_ctx)

    R = root.state_
    if verify_r(R, root):
        print("R computed success")
    else:
        print("R computation failed")

    tweaked_pubkey_ctx = apply_tweaks(root.keyagg_ctx, tweaks, is_xonly)
    assert(schnorr_verify(msg, get_xonly_pk(tweaked_pubkey_ctx), root.state_ + root.out_))


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
tweak_example()