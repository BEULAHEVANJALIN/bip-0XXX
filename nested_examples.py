from tree import parse_forest, print_tree
import secrets
from reference import *

def example1():
    root = parse_forest("Alice(Bob,Carol),Dave", root_name="Abby")
    print("Nested musig 2 example as per paper")
    print_tree(root)
    msg = secrets.token_bytes(32)
    tweaks = [secrets.token_bytes(32) for _ in range(3)] # 3 random tweaks to be applied on root pubkey
    aggpk = apply_tweaks(root.keyagg_ctx, tweaks, [True, False])

    print("Round 1 starts")