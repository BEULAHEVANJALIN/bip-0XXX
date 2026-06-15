from tree import Node
import secrets
from reference import *

def key_gen(node: Node):
    node.sk = secrets.token_bytes(32)
    node.pk = individual_pk(node.sk)

def key_gen_tree(node: Node):
    if node.is_leaf():
        return key_gen(node)
    else:
        for w in node.children:
            key_gen(w)
        child_pks =  [w.pk for w in node.children]
        node.keyagg_ctx = key_agg(child_pks)


def round1(node: Node, aggpk: XonlyPk = None, msg: bytes = None, extra_in = None):
    if node.is_leaf():
        (secnonce, pubnonce) = nonce_gen(node.sk, node.pk, aggpk, msg, extra_in)
        node.out = pubnonce
        node.state = secnonce
    else:
        for w in node.children:
            round1(w, aggpk, msg, extra_in)
        node.out_internal = nonce_agg([w.out for w in node.children])
        node.out = nonce_agg_ext(node.out_internal, PlainPk(cbytes(node.keyagg_ctx.Q)))

def round2(node: Node, aggothernonce_path: List[bytes], pubkey_tree: List[List[PlainPk]], tweaks: List[bytes], is_xonly: List[bool], msg: bytes, rand: Optional[bytes]):
    pass
