from tree import Node
import secrets
from reference import *

def key_gen(node: Node):
    node.sk = secrets.token_bytes(32)
    node.pk = individual_pk(node.sk)

def key_gen_tree(node: Node):
    if node.is_leaf():
        key_gen(node)
    else:
        for w in node.children:
            key_gen_tree(w)
        child_pks =  [w.pk for w in node.children]
        node.keyagg_ctx = key_agg(child_pks)
        node.pk = PlainPk(cbytes(node.keyagg_ctx.Q))


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

def round2(node: Node, nonce_path: List[bytes], pk_tree: List[List[PlainPk]], msg: bytes, tweaks: List[bytes] = [], is_xonly: List[bool] = [], rand:bytes = None):
    if node.is_leaf():
        session_ctx = SessionContext(nonce_path, pk_tree, tweaks, is_xonly, msg)
        final_nonce, psig = sign(node.state, node.sk, session_ctx)
        node.out_ = psig
        node.state_ = final_nonce
    else:
        nonce_path = nonce_path + [node.out_internal]
        for w in node.children:
            siblings = [u.pk for u in node.children if u.pk != w.pk]
            pk_tree = pk_tree + [siblings]
            round2(w, nonce_path, pk_tree, msg, tweaks, is_xonly, rand)

        node.state_ = node.children[0].state_ # same for every node
        psigs = [w.out_ for w in node.children]

        # Aggregating without tweaks
        s = 0
        for i in range(len(psigs)):
            s_i = int_from_bytes(psigs[i])
            if s_i >= n:
                raise InvalidContributionError(i, "psig")
            s = (s + s_i) % n
        node.out_ = bytes_from_int(s)
