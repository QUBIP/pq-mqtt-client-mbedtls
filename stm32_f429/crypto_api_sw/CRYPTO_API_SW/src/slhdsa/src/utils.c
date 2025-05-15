#include <string.h>

#include "utils.h"

#include "address.h"
#include "hash.h"
#include "params.h"
#include "thash.h"

/**
 * Converts the value of 'in' to 'outlen' bytes in big-endian byte order.
 */
void ull_to_bytes(unsigned char *out, unsigned int outlen,
                  unsigned long long in) {
    int i;

    /* Iterate over out in decreasing order, for big-endianness. */
    for (i = (signed int)outlen - 1; i >= 0; i--) {
        out[i] = in & 0xff;
        in = in >> 8;
    }
}

void u32_to_bytes(unsigned char *out, uint32_t in) {
    out[0] = (unsigned char)(in >> 24);
    out[1] = (unsigned char)(in >> 16);
    out[2] = (unsigned char)(in >> 8);
    out[3] = (unsigned char)in;
}

/**
 * Converts the inlen bytes in 'in' from big-endian byte order to an integer.
 */
unsigned long long bytes_to_ull(const unsigned char *in, unsigned int inlen) {
    unsigned long long retval = 0;
    unsigned int i;

    for (i = 0; i < inlen; i++) {
        retval |= ((unsigned long long)in[i]) << (8 * (inlen - 1 - i));
    }
    return retval;
}

/**
 * Computes a root node given a leaf and an auth path.
 * Expects address to be complete other than the tree_height and tree_index.
 */
void compute_root_shake_128_f(unsigned char *root, const unsigned char *leaf,
    uint32_t leaf_idx, uint32_t idx_offset,
    const unsigned char *auth_path, uint32_t tree_height,
    const spx_ctx_shake_128_f *ctx, uint32_t addr[8]) {
    uint32_t i;
    unsigned char buffer[2 * SPX_N_SHAKE_128_F];

    /* If leaf_idx is odd (last bit = 1), current path element is a right child
       and auth_path has to go left. Otherwise it is the other way around. */
    if (leaf_idx & 1) {
        memcpy(buffer + SPX_N_SHAKE_128_F, leaf, SPX_N_SHAKE_128_F);
        memcpy(buffer, auth_path, SPX_N_SHAKE_128_F);
    } else {
        memcpy(buffer, leaf, SPX_N_SHAKE_128_F);
        memcpy(buffer + SPX_N_SHAKE_128_F, auth_path, SPX_N_SHAKE_128_F);
    }
    auth_path += SPX_N_SHAKE_128_F;

    for (i = 0; i < tree_height - 1; i++) {
        leaf_idx >>= 1;
        idx_offset >>= 1;
        /* Set the address of the node we're creating. */
        set_tree_height(addr, i + 1);
        set_tree_index(addr, leaf_idx + idx_offset);

        /* Pick the right or left neighbor, depending on parity of the node. */
        if (leaf_idx & 1) {
            thash_shake_128_f(buffer + SPX_N_SHAKE_128_F, buffer, 2, ctx, addr);
            memcpy(buffer, auth_path, SPX_N_SHAKE_128_F);
        } else {
            thash_shake_128_f(buffer, buffer, 2, ctx, addr);
            memcpy(buffer + SPX_N_SHAKE_128_F, auth_path, SPX_N_SHAKE_128_F);
        }
        auth_path += SPX_N_SHAKE_128_F;
    }

    /* The last iteration is exceptional; we do not copy an auth_path node. */
    leaf_idx >>= 1;
    idx_offset >>= 1;
    set_tree_height(addr, tree_height);
    set_tree_index(addr, leaf_idx + idx_offset);
    thash_shake_128_f(root, buffer, 2, ctx, addr);
}
void compute_root_shake_128_s(unsigned char* root, const unsigned char* leaf,
    uint32_t leaf_idx, uint32_t idx_offset,
    const unsigned char* auth_path, uint32_t tree_height,
    const spx_ctx_shake_128_s* ctx, uint32_t addr[8]) {
    uint32_t i;
    unsigned char buffer[2 * SPX_N_SHAKE_128_S];

    /* If leaf_idx is odd (last bit = 1), current path element is a right child
       and auth_path has to go left. Otherwise it is the other way around. */
    if (leaf_idx & 1) {
        memcpy(buffer + SPX_N_SHAKE_128_S, leaf, SPX_N_SHAKE_128_S);
        memcpy(buffer, auth_path, SPX_N_SHAKE_128_S);
    }
    else {
        memcpy(buffer, leaf, SPX_N_SHAKE_128_S);
        memcpy(buffer + SPX_N_SHAKE_128_S, auth_path, SPX_N_SHAKE_128_S);
    }
    auth_path += SPX_N_SHAKE_128_S;

    for (i = 0; i < tree_height - 1; i++) {
        leaf_idx >>= 1;
        idx_offset >>= 1;
        /* Set the address of the node we're creating. */
        set_tree_height(addr, i + 1);
        set_tree_index(addr, leaf_idx + idx_offset);

        /* Pick the right or left neighbor, depending on parity of the node. */
        if (leaf_idx & 1) {
            thash_shake_128_s(buffer + SPX_N_SHAKE_128_S, buffer, 2, ctx, addr);
            memcpy(buffer, auth_path, SPX_N_SHAKE_128_S);
        }
        else {
            thash_shake_128_s(buffer, buffer, 2, ctx, addr);
            memcpy(buffer + SPX_N_SHAKE_128_S, auth_path, SPX_N_SHAKE_128_S);
        }
        auth_path += SPX_N_SHAKE_128_S;
    }

    /* The last iteration is exceptional; we do not copy an auth_path node. */
    leaf_idx >>= 1;
    idx_offset >>= 1;
    set_tree_height(addr, tree_height);
    set_tree_index(addr, leaf_idx + idx_offset);
    thash_shake_128_s(root, buffer, 2, ctx, addr);
}

void compute_root_shake_192_f(unsigned char* root, const unsigned char* leaf,
    uint32_t leaf_idx, uint32_t idx_offset,
    const unsigned char* auth_path, uint32_t tree_height,
    const spx_ctx_shake_192_f* ctx, uint32_t addr[8]) {
    uint32_t i;
    unsigned char buffer[2 * SPX_N_SHAKE_192_F];

    /* If leaf_idx is odd (last bit = 1), current path element is a right child
       and auth_path has to go left. Otherwise it is the other way around. */
    if (leaf_idx & 1) {
        memcpy(buffer + SPX_N_SHAKE_192_F, leaf, SPX_N_SHAKE_192_F);
        memcpy(buffer, auth_path, SPX_N_SHAKE_192_F);
    }
    else {
        memcpy(buffer, leaf, SPX_N_SHAKE_192_F);
        memcpy(buffer + SPX_N_SHAKE_192_F, auth_path, SPX_N_SHAKE_192_F);
    }
    auth_path += SPX_N_SHAKE_192_F;

    for (i = 0; i < tree_height - 1; i++) {
        leaf_idx >>= 1;
        idx_offset >>= 1;
        /* Set the address of the node we're creating. */
        set_tree_height(addr, i + 1);
        set_tree_index(addr, leaf_idx + idx_offset);

        /* Pick the right or left neighbor, depending on parity of the node. */
        if (leaf_idx & 1) {
            thash_shake_192_f(buffer + SPX_N_SHAKE_192_F, buffer, 2, ctx, addr);
            memcpy(buffer, auth_path, SPX_N_SHAKE_192_F);
        }
        else {
            thash_shake_192_f(buffer, buffer, 2, ctx, addr);
            memcpy(buffer + SPX_N_SHAKE_192_F, auth_path, SPX_N_SHAKE_192_F);
        }
        auth_path += SPX_N_SHAKE_192_F;
    }

    /* The last iteration is exceptional; we do not copy an auth_path node. */
    leaf_idx >>= 1;
    idx_offset >>= 1;
    set_tree_height(addr, tree_height);
    set_tree_index(addr, leaf_idx + idx_offset);
    thash_shake_192_f(root, buffer, 2, ctx, addr);
}
void compute_root_shake_192_s(unsigned char* root, const unsigned char* leaf,
    uint32_t leaf_idx, uint32_t idx_offset,
    const unsigned char* auth_path, uint32_t tree_height,
    const spx_ctx_shake_192_s* ctx, uint32_t addr[8]) {
    uint32_t i;
    unsigned char buffer[2 * SPX_N_SHAKE_192_S];

    /* If leaf_idx is odd (last bit = 1), current path element is a right child
       and auth_path has to go left. Otherwise it is the other way around. */
    if (leaf_idx & 1) {
        memcpy(buffer + SPX_N_SHAKE_192_S, leaf, SPX_N_SHAKE_192_S);
        memcpy(buffer, auth_path, SPX_N_SHAKE_192_S);
    }
    else {
        memcpy(buffer, leaf, SPX_N_SHAKE_192_S);
        memcpy(buffer + SPX_N_SHAKE_192_S, auth_path, SPX_N_SHAKE_192_S);
    }
    auth_path += SPX_N_SHAKE_192_S;

    for (i = 0; i < tree_height - 1; i++) {
        leaf_idx >>= 1;
        idx_offset >>= 1;
        /* Set the address of the node we're creating. */
        set_tree_height(addr, i + 1);
        set_tree_index(addr, leaf_idx + idx_offset);

        /* Pick the right or left neighbor, depending on parity of the node. */
        if (leaf_idx & 1) {
            thash_shake_192_s(buffer + SPX_N_SHAKE_192_S, buffer, 2, ctx, addr);
            memcpy(buffer, auth_path, SPX_N_SHAKE_192_S);
        }
        else {
            thash_shake_192_s(buffer, buffer, 2, ctx, addr);
            memcpy(buffer + SPX_N_SHAKE_192_S, auth_path, SPX_N_SHAKE_192_S);
        }
        auth_path += SPX_N_SHAKE_192_S;
    }

    /* The last iteration is exceptional; we do not copy an auth_path node. */
    leaf_idx >>= 1;
    idx_offset >>= 1;
    set_tree_height(addr, tree_height);
    set_tree_index(addr, leaf_idx + idx_offset);
    thash_shake_192_s(root, buffer, 2, ctx, addr);
}

void compute_root_shake_256_f(unsigned char* root, const unsigned char* leaf,
    uint32_t leaf_idx, uint32_t idx_offset,
    const unsigned char* auth_path, uint32_t tree_height,
    const spx_ctx_shake_256_f* ctx, uint32_t addr[8]) {
    uint32_t i;
    unsigned char buffer[2 * SPX_N_SHAKE_256_F];

    /* If leaf_idx is odd (last bit = 1), current path element is a right child
       and auth_path has to go left. Otherwise it is the other way around. */
    if (leaf_idx & 1) {
        memcpy(buffer + SPX_N_SHAKE_256_F, leaf, SPX_N_SHAKE_256_F);
        memcpy(buffer, auth_path, SPX_N_SHAKE_256_F);
    }
    else {
        memcpy(buffer, leaf, SPX_N_SHAKE_256_F);
        memcpy(buffer + SPX_N_SHAKE_256_F, auth_path, SPX_N_SHAKE_256_F);
    }
    auth_path += SPX_N_SHAKE_256_F;

    for (i = 0; i < tree_height - 1; i++) {
        leaf_idx >>= 1;
        idx_offset >>= 1;
        /* Set the address of the node we're creating. */
        set_tree_height(addr, i + 1);
        set_tree_index(addr, leaf_idx + idx_offset);

        /* Pick the right or left neighbor, depending on parity of the node. */
        if (leaf_idx & 1) {
            thash_shake_256_f(buffer + SPX_N_SHAKE_256_F, buffer, 2, ctx, addr);
            memcpy(buffer, auth_path, SPX_N_SHAKE_256_F);
        }
        else {
            thash_shake_256_f(buffer, buffer, 2, ctx, addr);
            memcpy(buffer + SPX_N_SHAKE_256_F, auth_path, SPX_N_SHAKE_256_F);
        }
        auth_path += SPX_N_SHAKE_256_F;
    }

    /* The last iteration is exceptional; we do not copy an auth_path node. */
    leaf_idx >>= 1;
    idx_offset >>= 1;
    set_tree_height(addr, tree_height);
    set_tree_index(addr, leaf_idx + idx_offset);
    thash_shake_256_f(root, buffer, 2, ctx, addr);
}
void compute_root_shake_256_s(unsigned char* root, const unsigned char* leaf,
    uint32_t leaf_idx, uint32_t idx_offset,
    const unsigned char* auth_path, uint32_t tree_height,
    const spx_ctx_shake_256_s* ctx, uint32_t addr[8]) {
    uint32_t i;
    unsigned char buffer[2 * SPX_N_SHAKE_256_S];

    /* If leaf_idx is odd (last bit = 1), current path element is a right child
       and auth_path has to go left. Otherwise it is the other way around. */
    if (leaf_idx & 1) {
        memcpy(buffer + SPX_N_SHAKE_256_S, leaf, SPX_N_SHAKE_256_S);
        memcpy(buffer, auth_path, SPX_N_SHAKE_256_S);
    }
    else {
        memcpy(buffer, leaf, SPX_N_SHAKE_256_S);
        memcpy(buffer + SPX_N_SHAKE_256_S, auth_path, SPX_N_SHAKE_256_S);
    }
    auth_path += SPX_N_SHAKE_256_S;

    for (i = 0; i < tree_height - 1; i++) {
        leaf_idx >>= 1;
        idx_offset >>= 1;
        /* Set the address of the node we're creating. */
        set_tree_height(addr, i + 1);
        set_tree_index(addr, leaf_idx + idx_offset);

        /* Pick the right or left neighbor, depending on parity of the node. */
        if (leaf_idx & 1) {
            thash_shake_256_s(buffer + SPX_N_SHAKE_256_S, buffer, 2, ctx, addr);
            memcpy(buffer, auth_path, SPX_N_SHAKE_256_S);
        }
        else {
            thash_shake_256_s(buffer, buffer, 2, ctx, addr);
            memcpy(buffer + SPX_N_SHAKE_256_S, auth_path, SPX_N_SHAKE_256_S);
        }
        auth_path += SPX_N_SHAKE_256_S;
    }

    /* The last iteration is exceptional; we do not copy an auth_path node. */
    leaf_idx >>= 1;
    idx_offset >>= 1;
    set_tree_height(addr, tree_height);
    set_tree_index(addr, leaf_idx + idx_offset);
    thash_shake_256_s(root, buffer, 2, ctx, addr);
}

/**
 * For a given leaf index, computes the authentication path and the resulting
 * root node using Merkle's TreeHash algorithm.
 * Expects the layer and tree parts of the tree_addr to be set, as well as the
 * tree type (i.e. SPX_ADDR_TYPE_HASHTREE or SPX_ADDR_TYPE_FORSTREE).
 * Applies the offset idx_offset to indices before building addresses, so that
 * it is possible to continue counting indices across trees.
 */
void treehash_shake_128_f(unsigned char *root, unsigned char *auth_path, const spx_ctx_shake_128_f *ctx,
              uint32_t leaf_idx, uint32_t idx_offset, uint32_t tree_height,
              void (*gen_leaf)(
                  unsigned char * /* leaf */,
                  const spx_ctx_shake_128_f * /* ctx */,
                  uint32_t /* addr_idx */, const uint32_t[8] /* tree_addr */),
              uint32_t tree_addr[8]) {
    PQCLEAN_VLA(uint8_t, stack, (tree_height + 1)*SPX_N_SHAKE_128_F);
    PQCLEAN_VLA(unsigned int, heights, tree_height + 1);
    unsigned int offset = 0;
    uint32_t idx;
    uint32_t tree_idx;

    for (idx = 0; idx < (uint32_t)(1 << tree_height); idx++) {
        /* Add the next leaf node to the stack. */
        gen_leaf(stack + offset * SPX_N_SHAKE_128_F, ctx, idx + idx_offset, tree_addr);
        offset++;
        heights[offset - 1] = 0;

        /* If this is a node we need for the auth path.. */
        if ((leaf_idx ^ 0x1) == idx) {
            memcpy(auth_path, stack + (offset - 1)* SPX_N_SHAKE_128_F, SPX_N_SHAKE_128_F);
        }

        /* While the top-most nodes are of equal height.. */
        while (offset >= 2 && heights[offset - 1] == heights[offset - 2]) {
            /* Compute index of the new node, in the next layer. */
            tree_idx = (idx >> (heights[offset - 1] + 1));

            /* Set the address of the node we're creating. */
            set_tree_height(tree_addr, heights[offset - 1] + 1);
            set_tree_index(tree_addr,
                           tree_idx + (idx_offset >> (heights[offset - 1] + 1)));
            /* Hash the top-most nodes from the stack together. */
            thash_shake_128_f(stack + (offset - 2)* SPX_N_SHAKE_128_F,
                  stack + (offset - 2)* SPX_N_SHAKE_128_F, 2, ctx, tree_addr);
            offset--;
            /* Note that the top-most node is now one layer higher. */
            heights[offset - 1]++;

            /* If this is a node we need for the auth path.. */
            if (((leaf_idx >> heights[offset - 1]) ^ 0x1) == tree_idx) {
                memcpy(auth_path + heights[offset - 1]* SPX_N_SHAKE_128_F,
                       stack + (offset - 1)* SPX_N_SHAKE_128_F, SPX_N_SHAKE_128_F);
            }
        }
    }
    memcpy(root, stack, SPX_N_SHAKE_128_F);
}
void treehash_shake_128_s(unsigned char* root, unsigned char* auth_path, const spx_ctx_shake_128_s* ctx,
    uint32_t leaf_idx, uint32_t idx_offset, uint32_t tree_height,
    void (*gen_leaf)(
        unsigned char* /* leaf */,
        const spx_ctx_shake_128_s* /* ctx */,
        uint32_t /* addr_idx */, const uint32_t[8] /* tree_addr */),
    uint32_t tree_addr[8]) {
    PQCLEAN_VLA(uint8_t, stack, (tree_height + 1) * SPX_N_SHAKE_128_S);
    PQCLEAN_VLA(unsigned int, heights, tree_height + 1);
    unsigned int offset = 0;
    uint32_t idx;
    uint32_t tree_idx;

    for (idx = 0; idx < (uint32_t)(1 << tree_height); idx++) {
        /* Add the next leaf node to the stack. */
        gen_leaf(stack + offset * SPX_N_SHAKE_128_S, ctx, idx + idx_offset, tree_addr);
        offset++;
        heights[offset - 1] = 0;

        /* If this is a node we need for the auth path.. */
        if ((leaf_idx ^ 0x1) == idx) {
            memcpy(auth_path, stack + (offset - 1) * SPX_N_SHAKE_128_S, SPX_N_SHAKE_128_S);
        }

        /* While the top-most nodes are of equal height.. */
        while (offset >= 2 && heights[offset - 1] == heights[offset - 2]) {
            /* Compute index of the new node, in the next layer. */
            tree_idx = (idx >> (heights[offset - 1] + 1));

            /* Set the address of the node we're creating. */
            set_tree_height(tree_addr, heights[offset - 1] + 1);
            set_tree_index(tree_addr,
                tree_idx + (idx_offset >> (heights[offset - 1] + 1)));
            /* Hash the top-most nodes from the stack together. */
            thash_shake_128_s(stack + (offset - 2) * SPX_N_SHAKE_128_S,
                stack + (offset - 2) * SPX_N_SHAKE_128_S, 2, ctx, tree_addr);
            offset--;
            /* Note that the top-most node is now one layer higher. */
            heights[offset - 1]++;

            /* If this is a node we need for the auth path.. */
            if (((leaf_idx >> heights[offset - 1]) ^ 0x1) == tree_idx) {
                memcpy(auth_path + heights[offset - 1] * SPX_N_SHAKE_128_S,
                    stack + (offset - 1) * SPX_N_SHAKE_128_S, SPX_N_SHAKE_128_S);
            }
        }
    }
    memcpy(root, stack, SPX_N_SHAKE_128_S);
}

void treehash_shake_192_f(unsigned char* root, unsigned char* auth_path, const spx_ctx_shake_192_f* ctx,
    uint32_t leaf_idx, uint32_t idx_offset, uint32_t tree_height,
    void (*gen_leaf)(
        unsigned char* /* leaf */,
        const spx_ctx_shake_192_f* /* ctx */,
        uint32_t /* addr_idx */, const uint32_t[8] /* tree_addr */),
    uint32_t tree_addr[8]) {
    PQCLEAN_VLA(uint8_t, stack, (tree_height + 1) * SPX_N_SHAKE_192_F);
    PQCLEAN_VLA(unsigned int, heights, tree_height + 1);
    unsigned int offset = 0;
    uint32_t idx;
    uint32_t tree_idx;

    for (idx = 0; idx < (uint32_t)(1 << tree_height); idx++) {
        /* Add the next leaf node to the stack. */
        gen_leaf(stack + offset * SPX_N_SHAKE_192_F, ctx, idx + idx_offset, tree_addr);
        offset++;
        heights[offset - 1] = 0;

        /* If this is a node we need for the auth path.. */
        if ((leaf_idx ^ 0x1) == idx) {
            memcpy(auth_path, stack + (offset - 1) * SPX_N_SHAKE_192_F, SPX_N_SHAKE_192_F);
        }

        /* While the top-most nodes are of equal height.. */
        while (offset >= 2 && heights[offset - 1] == heights[offset - 2]) {
            /* Compute index of the new node, in the next layer. */
            tree_idx = (idx >> (heights[offset - 1] + 1));

            /* Set the address of the node we're creating. */
            set_tree_height(tree_addr, heights[offset - 1] + 1);
            set_tree_index(tree_addr,
                tree_idx + (idx_offset >> (heights[offset - 1] + 1)));
            /* Hash the top-most nodes from the stack together. */
            thash_shake_192_f(stack + (offset - 2) * SPX_N_SHAKE_192_F,
                stack + (offset - 2) * SPX_N_SHAKE_192_F, 2, ctx, tree_addr);
            offset--;
            /* Note that the top-most node is now one layer higher. */
            heights[offset - 1]++;

            /* If this is a node we need for the auth path.. */
            if (((leaf_idx >> heights[offset - 1]) ^ 0x1) == tree_idx) {
                memcpy(auth_path + heights[offset - 1] * SPX_N_SHAKE_192_F,
                    stack + (offset - 1) * SPX_N_SHAKE_192_F, SPX_N_SHAKE_192_F);
            }
        }
    }
    memcpy(root, stack, SPX_N_SHAKE_192_F);
}
void treehash_shake_192_s(unsigned char* root, unsigned char* auth_path, const spx_ctx_shake_192_s* ctx,
    uint32_t leaf_idx, uint32_t idx_offset, uint32_t tree_height,
    void (*gen_leaf)(
        unsigned char* /* leaf */,
        const spx_ctx_shake_192_s* /* ctx */,
        uint32_t /* addr_idx */, const uint32_t[8] /* tree_addr */),
    uint32_t tree_addr[8]) {
    PQCLEAN_VLA(uint8_t, stack, (tree_height + 1) * SPX_N_SHAKE_192_S);
    PQCLEAN_VLA(unsigned int, heights, tree_height + 1);
    unsigned int offset = 0;
    uint32_t idx;
    uint32_t tree_idx;

    for (idx = 0; idx < (uint32_t)(1 << tree_height); idx++) {
        /* Add the next leaf node to the stack. */
        gen_leaf(stack + offset * SPX_N_SHAKE_192_S, ctx, idx + idx_offset, tree_addr);
        offset++;
        heights[offset - 1] = 0;

        /* If this is a node we need for the auth path.. */
        if ((leaf_idx ^ 0x1) == idx) {
            memcpy(auth_path, stack + (offset - 1) * SPX_N_SHAKE_192_S, SPX_N_SHAKE_192_S);
        }

        /* While the top-most nodes are of equal height.. */
        while (offset >= 2 && heights[offset - 1] == heights[offset - 2]) {
            /* Compute index of the new node, in the next layer. */
            tree_idx = (idx >> (heights[offset - 1] + 1));

            /* Set the address of the node we're creating. */
            set_tree_height(tree_addr, heights[offset - 1] + 1);
            set_tree_index(tree_addr,
                tree_idx + (idx_offset >> (heights[offset - 1] + 1)));
            /* Hash the top-most nodes from the stack together. */
            thash_shake_192_s(stack + (offset - 2) * SPX_N_SHAKE_192_S,
                stack + (offset - 2) * SPX_N_SHAKE_192_S, 2, ctx, tree_addr);
            offset--;
            /* Note that the top-most node is now one layer higher. */
            heights[offset - 1]++;

            /* If this is a node we need for the auth path.. */
            if (((leaf_idx >> heights[offset - 1]) ^ 0x1) == tree_idx) {
                memcpy(auth_path + heights[offset - 1] * SPX_N_SHAKE_192_S,
                    stack + (offset - 1) * SPX_N_SHAKE_192_S, SPX_N_SHAKE_192_S);
            }
        }
    }
    memcpy(root, stack, SPX_N_SHAKE_192_S);
}

void treehash_shake_256_f(unsigned char* root, unsigned char* auth_path, const spx_ctx_shake_256_f* ctx,
    uint32_t leaf_idx, uint32_t idx_offset, uint32_t tree_height,
    void (*gen_leaf)(
        unsigned char* /* leaf */,
        const spx_ctx_shake_256_f* /* ctx */,
        uint32_t /* addr_idx */, const uint32_t[8] /* tree_addr */),
    uint32_t tree_addr[8]) {
    PQCLEAN_VLA(uint8_t, stack, (tree_height + 1) * SPX_N_SHAKE_256_F);
    PQCLEAN_VLA(unsigned int, heights, tree_height + 1);
    unsigned int offset = 0;
    uint32_t idx;
    uint32_t tree_idx;

    for (idx = 0; idx < (uint32_t)(1 << tree_height); idx++) {
        /* Add the next leaf node to the stack. */
        gen_leaf(stack + offset * SPX_N_SHAKE_256_F, ctx, idx + idx_offset, tree_addr);
        offset++;
        heights[offset - 1] = 0;

        /* If this is a node we need for the auth path.. */
        if ((leaf_idx ^ 0x1) == idx) {
            memcpy(auth_path, stack + (offset - 1) * SPX_N_SHAKE_256_F, SPX_N_SHAKE_256_F);
        }

        /* While the top-most nodes are of equal height.. */
        while (offset >= 2 && heights[offset - 1] == heights[offset - 2]) {
            /* Compute index of the new node, in the next layer. */
            tree_idx = (idx >> (heights[offset - 1] + 1));

            /* Set the address of the node we're creating. */
            set_tree_height(tree_addr, heights[offset - 1] + 1);
            set_tree_index(tree_addr,
                tree_idx + (idx_offset >> (heights[offset - 1] + 1)));
            /* Hash the top-most nodes from the stack together. */
            thash_shake_256_f(stack + (offset - 2) * SPX_N_SHAKE_256_F,
                stack + (offset - 2) * SPX_N_SHAKE_256_F, 2, ctx, tree_addr);
            offset--;
            /* Note that the top-most node is now one layer higher. */
            heights[offset - 1]++;

            /* If this is a node we need for the auth path.. */
            if (((leaf_idx >> heights[offset - 1]) ^ 0x1) == tree_idx) {
                memcpy(auth_path + heights[offset - 1] * SPX_N_SHAKE_256_F,
                    stack + (offset - 1) * SPX_N_SHAKE_256_F, SPX_N_SHAKE_256_F);
            }
        }
    }
    memcpy(root, stack, SPX_N_SHAKE_256_F);
}
void treehash_shake_256_s(unsigned char* root, unsigned char* auth_path, const spx_ctx_shake_256_s* ctx,
    uint32_t leaf_idx, uint32_t idx_offset, uint32_t tree_height,
    void (*gen_leaf)(
        unsigned char* /* leaf */,
        const spx_ctx_shake_256_s* /* ctx */,
        uint32_t /* addr_idx */, const uint32_t[8] /* tree_addr */),
    uint32_t tree_addr[8]) {
    PQCLEAN_VLA(uint8_t, stack, (tree_height + 1) * SPX_N_SHAKE_256_S);
    PQCLEAN_VLA(unsigned int, heights, tree_height + 1);
    unsigned int offset = 0;
    uint32_t idx;
    uint32_t tree_idx;

    for (idx = 0; idx < (uint32_t)(1 << tree_height); idx++) {
        /* Add the next leaf node to the stack. */
        gen_leaf(stack + offset * SPX_N_SHAKE_256_S, ctx, idx + idx_offset, tree_addr);
        offset++;
        heights[offset - 1] = 0;

        /* If this is a node we need for the auth path.. */
        if ((leaf_idx ^ 0x1) == idx) {
            memcpy(auth_path, stack + (offset - 1) * SPX_N_SHAKE_256_S, SPX_N_SHAKE_256_S);
        }

        /* While the top-most nodes are of equal height.. */
        while (offset >= 2 && heights[offset - 1] == heights[offset - 2]) {
            /* Compute index of the new node, in the next layer. */
            tree_idx = (idx >> (heights[offset - 1] + 1));

            /* Set the address of the node we're creating. */
            set_tree_height(tree_addr, heights[offset - 1] + 1);
            set_tree_index(tree_addr,
                tree_idx + (idx_offset >> (heights[offset - 1] + 1)));
            /* Hash the top-most nodes from the stack together. */
            thash_shake_256_s(stack + (offset - 2) * SPX_N_SHAKE_256_S,
                stack + (offset - 2) * SPX_N_SHAKE_256_S, 2, ctx, tree_addr);
            offset--;
            /* Note that the top-most node is now one layer higher. */
            heights[offset - 1]++;

            /* If this is a node we need for the auth path.. */
            if (((leaf_idx >> heights[offset - 1]) ^ 0x1) == tree_idx) {
                memcpy(auth_path + heights[offset - 1] * SPX_N_SHAKE_256_S,
                    stack + (offset - 1) * SPX_N_SHAKE_256_S, SPX_N_SHAKE_256_S);
            }
        }
    }
    memcpy(root, stack, SPX_N_SHAKE_256_S);
}