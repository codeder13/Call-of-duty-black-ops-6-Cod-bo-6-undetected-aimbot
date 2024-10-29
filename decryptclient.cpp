uintptr_t decrypt_client_info()
{
        uint64_t mb = st::module_base;
        uint64_t rax = mb, rbx = mb, rcx = mb, rdx = mb, rdi = mb, rsi = mb, r8 = mb, r9 = mb, r10 = mb, r11 = mb, r12 = mb, r13 = mb, r14 = mb, r15 = mb;
 
        rbx ^= rbx;
        if(!rbx)
                return rbx;
 
        rdx = st::peb;          //mov rdx, gs:[rax]
        return rbx;
};
 
uintptr_t decrypt_client_base(uintptr_t client_info)
{
        uint64_t mb = st::module_base;
        uint64_t rax = mb, rbx = mb, rcx = mb, rdx = mb, rdi = mb, rsi = mb, r8 = mb, r9 = mb, r10 = mb, r11 = mb, r12 = mb, r13 = mb, r14 = mb, r15 = mb;
 
        rax = p_mem.read64(client_info + 0x1d6e38);
        if(!rax)
                return rax;
 
        rdi = st::peb;          //mov rdi, gs:[rcx]
        rcx = rdi;              //mov rcx, rdi
        rcx = _rotl64(rcx, 0x23);               //rol rcx, 0x23
        rcx &= 0xF;
 
        switch(rcx)
        {
        case 0:
        {
                r10 = p_mem.read64(st::module_base + 0xB34D124);                //mov r10, [0x000000000816A7F7]
                rbx = st::module_base;          //lea rbx, [0xFFFFFFFFFCE1D6CC]
                rdx = st::module_base + 0x88F;          //lea rdx, [0xFFFFFFFFFCE1DF16]
                rax -= rdi;             //sub rax, rdi
                rcx = rax;              //mov rcx, rax
                rcx >>= 0x1A;           //shr rcx, 0x1A
                rax ^= rcx;             //xor rax, rcx
                rcx = rax;              //mov rcx, rax
                rcx >>= 0x34;           //shr rcx, 0x34
                rax ^= rcx;             //xor rax, rcx
                rcx = 0;                //and rcx, 0xFFFFFFFFC0000000
                rcx = _rotl64(rcx, 0x10);               //rol rcx, 0x10
                rcx ^= r10;             //xor rcx, r10
                rcx = _byteswap_uint64(rcx);            //bswap rcx
                rax *= p_mem.read64(rcx + 0xb);                 //imul rax, [rcx+0x0B]
                rcx = rdi;              //mov rcx, rdi
                rcx = ~rcx;             //not rcx
                rcx += rdx;             //add rcx, rdx
                rax ^= rcx;             //xor rax, rcx
                rcx = 0x3E5B494B0BC9589;                //mov rcx, 0x3E5B494B0BC9589
                rax += rcx;             //add rax, rcx
                rcx = 0xB4534A1037D072A0;               //mov rcx, 0xB4534A1037D072A0
                rax ^= rcx;             //xor rax, rcx
                rcx = 0x1E97CDD5447FA367;               //mov rcx, 0x1E97CDD5447FA367
                rax *= rcx;             //imul rax, rcx
                rax ^= rbx;             //xor rax, rbx
                return rax;
        }
        case 1:
        {
                r10 = p_mem.read64(st::module_base + 0xB34D124);                //mov r10, [0x000000000816A3D5]
                rbx = st::module_base + 0x2877C212;             //lea rbx, [0x00000000255994B0]
                rax += rdi;             //add rax, rdi
                rcx = 0xF86CA28E514302A5;               //mov rcx, 0xF86CA28E514302A5
                rax *= rcx;             //imul rax, rcx
                rcx = rax;              //mov rcx, rax
                rcx >>= 0xA;            //shr rcx, 0x0A
                rax ^= rcx;             //xor rax, rcx
                rcx = rax;              //mov rcx, rax
                rcx >>= 0x14;           //shr rcx, 0x14
                rax ^= rcx;             //xor rax, rcx
                rcx = rax;              //mov rcx, rax
                rcx >>= 0x28;           //shr rcx, 0x28
                rax ^= rcx;             //xor rax, rcx
                rcx = 0;                //and rcx, 0xFFFFFFFFC0000000
                rcx = _rotl64(rcx, 0x10);               //rol rcx, 0x10
                rcx ^= r10;             //xor rcx, r10
                rcx = _byteswap_uint64(rcx);            //bswap rcx
                rax *= p_mem.read64(rcx + 0xb);                 //imul rax, [rcx+0x0B]
                rcx = rax;              //mov rcx, rax
                rcx >>= 0x15;           //shr rcx, 0x15
                rax ^= rcx;             //xor rax, rcx
                rdx = rax;              //mov rdx, rax
                rdx >>= 0x2A;           //shr rdx, 0x2A
                rax ^= rdx;             //xor rax, rdx
                rcx = rdi;              //mov rcx, rdi
                rcx = ~rcx;             //not rcx
                rcx ^= rbx;             //xor rcx, rbx
                rax -= rcx;             //sub rax, rcx
                rcx = 0xF7CCBBD3120AB863;               //mov rcx, 0xF7CCBBD3120AB863
                rax *= rcx;             //imul rax, rcx
                return rax;
        }
        case 2:
        {
                r10 = p_mem.read64(st::module_base + 0xB34D124);                //mov r10, [0x0000000008169F41]
                rbx = st::module_base;          //lea rbx, [0xFFFFFFFFFCE1CE16]
                rcx = 0x92FE973BC919B075;               //mov rcx, 0x92FE973BC919B075
                rax *= rcx;             //imul rax, rcx
                rcx = rax;              //mov rcx, rax
                rdx = 0;                //and rdx, 0xFFFFFFFFC0000000
                rcx >>= 0x21;           //shr rcx, 0x21
                rdx = _rotl64(rdx, 0x10);               //rol rdx, 0x10
                rax ^= rcx;             //xor rax, rcx
                rdx ^= r10;             //xor rdx, r10
                rdx = _byteswap_uint64(rdx);            //bswap rdx
                rax *= p_mem.read64(rdx + 0xb);                 //imul rax, [rdx+0x0B]
                rcx = 0xE34613AF4FE4912D;               //mov rcx, 0xE34613AF4FE4912D
                rax += rcx;             //add rax, rcx
                rax += rbx;             //add rax, rbx
                rcx = 0xC0156C8A0FF87104;               //mov rcx, 0xC0156C8A0FF87104
                rax ^= rcx;             //xor rax, rcx
                rax -= rbx;             //sub rax, rbx
                rcx = rdi;              //mov rcx, rdi
                rcx -= rbx;             //sub rcx, rbx
                rcx += 0xFFFFFFFFFFFFB00E;              //add rcx, 0xFFFFFFFFFFFFB00E
                rax += rcx;             //add rax, rcx
                return rax;
        }
        case 3:
        {
                r10 = p_mem.read64(st::module_base + 0xB34D124);                //mov r10, [0x0000000008169BEB]
                rbx = st::module_base + 0x4B16137D;             //lea rbx, [0x0000000047F7DE31]
                rax += rdi;             //add rax, rdi
                rcx = rdi;              //mov rcx, rdi
                rcx = ~rcx;             //not rcx
                rcx += rbx;             //add rcx, rbx
                rax ^= rcx;             //xor rax, rcx
                rcx = rax;              //mov rcx, rax
                rcx >>= 0xE;            //shr rcx, 0x0E
                rax ^= rcx;             //xor rax, rcx
                rcx = rax;              //mov rcx, rax
                rcx >>= 0x1C;           //shr rcx, 0x1C
                rax ^= rcx;             //xor rax, rcx
                rcx = rax;              //mov rcx, rax
                rcx >>= 0x38;           //shr rcx, 0x38
                rax ^= rcx;             //xor rax, rcx
                rcx = 0;                //and rcx, 0xFFFFFFFFC0000000
                rcx = _rotl64(rcx, 0x10);               //rol rcx, 0x10
                rcx ^= r10;             //xor rcx, r10
                rcx = _byteswap_uint64(rcx);            //bswap rcx
                rax *= p_mem.read64(rcx + 0xb);                 //imul rax, [rcx+0x0B]
                rcx = 0x4992581A2BC4E671;               //mov rcx, 0x4992581A2BC4E671
                rax *= rcx;             //imul rax, rcx
                rcx = 0xCDF6777C866FF9F6;               //mov rcx, 0xCDF6777C866FF9F6
                rax ^= rcx;             //xor rax, rcx
                rcx = rax;              //mov rcx, rax
                rcx >>= 0x10;           //shr rcx, 0x10
                rax ^= rcx;             //xor rax, rcx
                rcx = rax;              //mov rcx, rax
                rcx >>= 0x20;           //shr rcx, 0x20
                rax ^= rcx;             //xor rax, rcx
                rax -= rdi;             //sub rax, rdi
                return rax;
        }
        case 4:
        {
                r10 = p_mem.read64(st::module_base + 0xB34D124);                //mov r10, [0x0000000008169682]
                rbx = st::module_base;          //lea rbx, [0xFFFFFFFFFCE1C557]
                rdx = rdi;              //mov rdx, rdi
                rdx = ~rdx;             //not rdx
                rcx = st::module_base + 0xE9DB;                 //lea rcx, [0xFFFFFFFFFCE2AD2C]
                rax += rcx;             //add rax, rcx
                rax += rdx;             //add rax, rdx
                rcx = rax;              //mov rcx, rax
                rcx >>= 0x1D;           //shr rcx, 0x1D
                rax ^= rcx;             //xor rax, rcx
                rcx = rax;              //mov rcx, rax
                rcx >>= 0x3A;           //shr rcx, 0x3A
                rax ^= rcx;             //xor rax, rcx
                rax ^= rbx;             //xor rax, rbx
                rcx = 0;                //and rcx, 0xFFFFFFFFC0000000
                rcx = _rotl64(rcx, 0x10);               //rol rcx, 0x10
                rcx ^= r10;             //xor rcx, r10
                rcx = _byteswap_uint64(rcx);            //bswap rcx
                rax *= p_mem.read64(rcx + 0xb);                 //imul rax, [rcx+0x0B]
                rax -= rbx;             //sub rax, rbx
                rcx = 0x3325677F68183F82;               //mov rcx, 0x3325677F68183F82
                rax ^= rcx;             //xor rax, rcx
                rcx = 0x1744B49C05D0AC25;               //mov rcx, 0x1744B49C05D0AC25
                rax *= rcx;             //imul rax, rcx
                return rax;
        }
        case 5:
        {
                r10 = p_mem.read64(st::module_base + 0xB34D124);                //mov r10, [0x00000000081691BA]
                rbx = st::module_base;          //lea rbx, [0xFFFFFFFFFCE1C08F]
                rcx = 0;                //and rcx, 0xFFFFFFFFC0000000
                rcx = _rotl64(rcx, 0x10);               //rol rcx, 0x10
                rcx ^= r10;             //xor rcx, r10
                rcx = _byteswap_uint64(rcx);            //bswap rcx
                rcx = p_mem.read64(rcx + 0xb);          //mov rcx, [rcx+0x0B]
                uintptr_t RSP_0x60;
                RSP_0x60 = 0x5D1C282C2B2067CD;          //mov rcx, 0x5D1C282C2B2067CD : RSP+0x60
                rcx *= RSP_0x60;                //imul rcx, [rsp+0x60]
                rax *= rcx;             //imul rax, rcx
                rdx = rdi;              //mov rdx, rdi
                rcx = st::module_base + 0x71A7;                 //lea rcx, [0xFFFFFFFFFCE23104]
                rdx *= rcx;             //imul rdx, rcx
                rcx = rax;              //mov rcx, rax
                rcx >>= 0x27;           //shr rcx, 0x27
                rdx ^= rcx;             //xor rdx, rcx
                rax ^= rdx;             //xor rax, rdx
                rax -= rbx;             //sub rax, rbx
                rax += 0xFFFFFFFFFFFF93BD;              //add rax, 0xFFFFFFFFFFFF93BD
                rax += rdi;             //add rax, rdi
                rcx = 0x41BAD1565F2012BD;               //mov rcx, 0x41BAD1565F2012BD
                rax -= rcx;             //sub rax, rcx
                rcx = 0xFFFFFFFFFFFFEA76;               //mov rcx, 0xFFFFFFFFFFFFEA76
                rcx -= rbx;             //sub rcx, rbx
                rax += rcx;             //add rax, rcx
                return rax;
        }
        case 6:
        {
                r11 = p_mem.read64(st::module_base + 0xB34D124);                //mov r11, [0x0000000008168D49]
                rbx = st::module_base;          //lea rbx, [0xFFFFFFFFFCE1BC12]
                rcx = 0x3FCC08C024F03C10;               //mov rcx, 0x3FCC08C024F03C10
                rax -= rcx;             //sub rax, rcx
                rdx = rax;              //mov rdx, rax
                rdx >>= 0x23;           //shr rdx, 0x23
                rdx ^= rax;             //xor rdx, rax
                rax = st::module_base + 0x5E8EF052;             //lea rax, [0x000000005B70AA24]
                rax *= rdi;             //imul rax, rdi
                rax += rdx;             //add rax, rdx
                rcx = 0x9048ECDC32DF2E7D;               //mov rcx, 0x9048ECDC32DF2E7D
                rax *= rcx;             //imul rax, rcx
                rdx = st::module_base + 0x776563BD;             //lea rdx, [0x0000000074471C8D]
                r8 = 0;                 //and r8, 0xFFFFFFFFC0000000
                r8 = _rotl64(r8, 0x10);                 //rol r8, 0x10
                rcx = rbx + 0xa4cd;             //lea rcx, [rbx+0xA4CD]
                rcx += rdi;             //add rcx, rdi
                rdx -= rdi;             //sub rdx, rdi
                rdx ^= rcx;             //xor rdx, rcx
                r8 ^= r11;              //xor r8, r11
                rax ^= rdx;             //xor rax, rdx
                rcx = 0x404F146600320847;               //mov rcx, 0x404F146600320847
                r8 = _byteswap_uint64(r8);              //bswap r8
                rax ^= rcx;             //xor rax, rcx
                rax *= p_mem.read64(r8 + 0xb);          //imul rax, [r8+0x0B]
                return rax;
        }
        case 7:
        {
                r9 = p_mem.read64(st::module_base + 0xB34D124);                 //mov r9, [0x000000000816890E]
                rbx = st::module_base;          //lea rbx, [0xFFFFFFFFFCE1B7E3]
                rcx = rax;              //mov rcx, rax
                rcx >>= 0x16;           //shr rcx, 0x16
                rax ^= rcx;             //xor rax, rcx
                rcx = rax;              //mov rcx, rax
                rcx >>= 0x2C;           //shr rcx, 0x2C
                rax ^= rcx;             //xor rax, rcx
                rcx = 0x966AB4410F2B287E;               //mov rcx, 0x966AB4410F2B287E
                rax ^= rcx;             //xor rax, rcx
                rcx = 0xE94D2AC9BF1D6687;               //mov rcx, 0xE94D2AC9BF1D6687
                rax *= rcx;             //imul rax, rcx
                rcx = 0;                //and rcx, 0xFFFFFFFFC0000000
                rcx = _rotl64(rcx, 0x10);               //rol rcx, 0x10
                rcx ^= r9;              //xor rcx, r9
                rcx = _byteswap_uint64(rcx);            //bswap rcx
                rcx = p_mem.read64(rcx + 0xb);          //mov rcx, [rcx+0x0B]
                uintptr_t RSP_0x48;
                RSP_0x48 = 0x60E5FDF266ED09A3;          //mov rcx, 0x60E5FDF266ED09A3 : RSP+0x48
                rcx *= RSP_0x48;                //imul rcx, [rsp+0x48]
                rax *= rcx;             //imul rax, rcx
                rcx = rax;              //mov rcx, rax
                rcx >>= 0x11;           //shr rcx, 0x11
                rax ^= rcx;             //xor rax, rcx
                rcx = rax;              //mov rcx, rax
                rcx >>= 0x22;           //shr rcx, 0x22
                rax ^= rcx;             //xor rax, rcx
                rcx = rdi + rbx * 1;            //lea rcx, [rdi+rbx*1]
                rax -= rcx;             //sub rax, rcx
                return rax;
        }
        case 8:
        {
                r10 = p_mem.read64(st::module_base + 0xB34D124);                //mov r10, [0x00000000081683C9]
                rdx = st::module_base + 0xCD18;                 //lea rdx, [0xFFFFFFFFFCE27F25]
                rcx = rax;              //mov rcx, rax
                rcx >>= 0x15;           //shr rcx, 0x15
                rax ^= rcx;             //xor rax, rcx
                rcx = rax;              //mov rcx, rax
                rcx >>= 0x2A;           //shr rcx, 0x2A
                rax ^= rcx;             //xor rax, rcx
                rcx = 0x24E42C3BF3769606;               //mov rcx, 0x24E42C3BF3769606
                rax ^= rcx;             //xor rax, rcx
                rcx = rax;              //mov rcx, rax
                rcx >>= 0x2;            //shr rcx, 0x02
                rax ^= rcx;             //xor rax, rcx
                rcx = rax;              //mov rcx, rax
                rcx >>= 0x4;            //shr rcx, 0x04
                rax ^= rcx;             //xor rax, rcx
                rcx = rax;              //mov rcx, rax
                rcx >>= 0x8;            //shr rcx, 0x08
                rax ^= rcx;             //xor rax, rcx
                rcx = rax;              //mov rcx, rax
                rcx >>= 0x10;           //shr rcx, 0x10
                rax ^= rcx;             //xor rax, rcx
                rcx = rax;              //mov rcx, rax
                rcx >>= 0x20;           //shr rcx, 0x20
                rax ^= rcx;             //xor rax, rcx
                rcx = rdi;              //mov rcx, rdi
                uintptr_t RSP_0x28;
                RSP_0x28 = st::module_base + 0x52DABDC0;                //lea rcx, [0x000000004FBC705E] : RSP+0x28
                rcx *= RSP_0x28;                //imul rcx, [rsp+0x28]
                rax += rcx;             //add rax, rcx
                rcx = 0x2A47B53E905688A9;               //mov rcx, 0x2A47B53E905688A9
                rax ^= rcx;             //xor rax, rcx
                rcx = 0;                //and rcx, 0xFFFFFFFFC0000000
                rcx = _rotl64(rcx, 0x10);               //rol rcx, 0x10
                rcx ^= r10;             //xor rcx, r10
                rcx = _byteswap_uint64(rcx);            //bswap rcx
                rcx = p_mem.read64(rcx + 0xb);          //mov rcx, [rcx+0x0B]
                uintptr_t RSP_0x68;
                RSP_0x68 = 0xC87022DA889255C7;          //mov rcx, 0xC87022DA889255C7 : RSP+0x68
                rcx *= RSP_0x68;                //imul rcx, [rsp+0x68]
                rax *= rcx;             //imul rax, rcx
                rcx = rdi;              //mov rcx, rdi
                rcx *= rdx;             //imul rcx, rdx
                rax += rcx;             //add rax, rcx
                return rax;
        }
        case 9:
        {
                r10 = p_mem.read64(st::module_base + 0xB34D124);                //mov r10, [0x0000000008167E23]
                rdx = st::module_base + 0x1803;                 //lea rdx, [0xFFFFFFFFFCE1C466]
                rcx = rdi;              //mov rcx, rdi
                rcx = ~rcx;             //not rcx
                uintptr_t RSP_0x50;
                RSP_0x50 = st::module_base + 0x4299DD2B;                //lea rcx, [0x000000003F7B8A23] : RSP+0x50
                rcx ^= RSP_0x50;                //xor rcx, [rsp+0x50]
                rax -= rcx;             //sub rax, rcx
                rcx = rax;              //mov rcx, rax
                rcx >>= 0x13;           //shr rcx, 0x13
                rax ^= rcx;             //xor rax, rcx
                rcx = rax;              //mov rcx, rax
                rcx >>= 0x26;           //shr rcx, 0x26
                rax ^= rcx;             //xor rax, rcx
                rcx = 0x558F697530DE0F7E;               //mov rcx, 0x558F697530DE0F7E
                rax -= rcx;             //sub rax, rcx
                rcx = rax;              //mov rcx, rax
                rcx >>= 0x1A;           //shr rcx, 0x1A
                rax ^= rcx;             //xor rax, rcx
                rcx = rax;              //mov rcx, rax
                rcx >>= 0x34;           //shr rcx, 0x34
                rax ^= rcx;             //xor rax, rcx
                rcx = 0x9AE713C32BDC087D;               //mov rcx, 0x9AE713C32BDC087D
                rax *= rcx;             //imul rax, rcx
                rcx = 0x3346C10DA1125ECB;               //mov rcx, 0x3346C10DA1125ECB
                rax ^= rcx;             //xor rax, rcx
                rcx = rdi;              //mov rcx, rdi
                rcx = ~rcx;             //not rcx
                rcx ^= rdx;             //xor rcx, rdx
                rax -= rcx;             //sub rax, rcx
                rcx = 0;                //and rcx, 0xFFFFFFFFC0000000
                rcx = _rotl64(rcx, 0x10);               //rol rcx, 0x10
                rcx ^= r10;             //xor rcx, r10
                rcx = _byteswap_uint64(rcx);            //bswap rcx
                rax *= p_mem.read64(rcx + 0xb);                 //imul rax, [rcx+0x0B]
                return rax;
        }
        case 10:
        {
                r9 = p_mem.read64(st::module_base + 0xB34D124);                 //mov r9, [0x00000000081678F1]
                rbx = st::module_base;          //lea rbx, [0xFFFFFFFFFCE1A7C6]
                rcx = 0x901B89255C3A3269;               //mov rcx, 0x901B89255C3A3269
                rax *= rcx;             //imul rax, rcx
                rcx = 0x63C8ACC6E4C1518E;               //mov rcx, 0x63C8ACC6E4C1518E
                rax ^= rcx;             //xor rax, rcx
                r11 = 0x9FB5A3DD22D4DF53;               //mov r11, 0x9FB5A3DD22D4DF53
                rax += r11;             //add rax, r11
                rcx = 0;                //and rcx, 0xFFFFFFFFC0000000
                rcx = _rotl64(rcx, 0x10);               //rol rcx, 0x10
                rcx ^= r9;              //xor rcx, r9
                rcx = _byteswap_uint64(rcx);            //bswap rcx
                rax *= p_mem.read64(rcx + 0xb);                 //imul rax, [rcx+0x0B]
                rcx = rax;              //mov rcx, rax
                rcx >>= 0x5;            //shr rcx, 0x05
                rax ^= rcx;             //xor rax, rcx
                rcx = rax;              //mov rcx, rax
                rcx >>= 0xA;            //shr rcx, 0x0A
                rax ^= rcx;             //xor rax, rcx
                rcx = rax;              //mov rcx, rax
                rcx >>= 0x14;           //shr rcx, 0x14
                rax ^= rcx;             //xor rax, rcx
                rcx = rax;              //mov rcx, rax
                rcx >>= 0x28;           //shr rcx, 0x28
                rax ^= rcx;             //xor rax, rcx
                rcx = rax;              //mov rcx, rax
                rcx >>= 0x10;           //shr rcx, 0x10
                rax ^= rcx;             //xor rax, rcx
                rcx = rax;              //mov rcx, rax
                rcx >>= 0x20;           //shr rcx, 0x20
                rax ^= rcx;             //xor rax, rcx
                rax ^= rbx;             //xor rax, rbx
                rax ^= rdi;             //xor rax, rdi
                return rax;
        }
        case 11:
        {
                r10 = p_mem.read64(st::module_base + 0xB34D124);                //mov r10, [0x00000000081673DC]
                rcx = rax;              //mov rcx, rax
                rcx >>= 0x14;           //shr rcx, 0x14
                rax ^= rcx;             //xor rax, rcx
                rcx = rax;              //mov rcx, rax
                rcx >>= 0x28;           //shr rcx, 0x28
                rax ^= rcx;             //xor rax, rcx
                rcx = 0x7CAB92A683B968CF;               //mov rcx, 0x7CAB92A683B968CF
                rax *= rcx;             //imul rax, rcx
                rcx = 0xFE4E124F05E07EE;                //mov rcx, 0xFE4E124F05E07EE
                rax ^= rcx;             //xor rax, rcx
                rdx = rdi;              //mov rdx, rdi
                rdx = ~rdx;             //not rdx
                rcx = st::module_base + 0x44902404;             //lea rcx, [0x000000004171C406]
                rax += rcx;             //add rax, rcx
                rax += rdx;             //add rax, rdx
                rcx = rdi;              //mov rcx, rdi
                rcx = ~rcx;             //not rcx
                uintptr_t RSP_0x50;
                RSP_0x50 = st::module_base + 0xD218;            //lea rcx, [0xFFFFFFFFFCE27456] : RSP+0x50
                rcx *= RSP_0x50;                //imul rcx, [rsp+0x50]
                rax += rcx;             //add rax, rcx
                rcx = 0x3C4AB6D70A4A16A3;               //mov rcx, 0x3C4AB6D70A4A16A3
                rax += rcx;             //add rax, rcx
                rcx = rax;              //mov rcx, rax
                rcx >>= 0x23;           //shr rcx, 0x23
                rax ^= rcx;             //xor rax, rcx
                rcx = 0;                //and rcx, 0xFFFFFFFFC0000000
                rcx = _rotl64(rcx, 0x10);               //rol rcx, 0x10
                rcx ^= r10;             //xor rcx, r10
                rcx = _byteswap_uint64(rcx);            //bswap rcx
                rax *= p_mem.read64(rcx + 0xb);                 //imul rax, [rcx+0x0B]
                return rax;
        }
        case 12:
        {
                r9 = p_mem.read64(st::module_base + 0xB34D124);                 //mov r9, [0x0000000008166F57]
                rbx = st::module_base;          //lea rbx, [0xFFFFFFFFFCE19E2C]
                rcx = 0;                //and rcx, 0xFFFFFFFFC0000000
                rcx = _rotl64(rcx, 0x10);               //rol rcx, 0x10
                rcx ^= r9;              //xor rcx, r9
                rcx = _byteswap_uint64(rcx);            //bswap rcx
                rax *= p_mem.read64(rcx + 0xb);                 //imul rax, [rcx+0x0B]
                rcx = rax;              //mov rcx, rax
                rcx >>= 0x14;           //shr rcx, 0x14
                rax ^= rcx;             //xor rax, rcx
                rcx = rax;              //mov rcx, rax
                rcx >>= 0x28;           //shr rcx, 0x28
                rax ^= rcx;             //xor rax, rcx
                rax ^= rbx;             //xor rax, rbx
                rcx = 0x3F725CD28463AFC1;               //mov rcx, 0x3F725CD28463AFC1
                rax -= rcx;             //sub rax, rcx
                rcx = 0x3E6A41E60D0633A;                //mov rcx, 0x3E6A41E60D0633A
                rax += rcx;             //add rax, rcx
                rax += rbx;             //add rax, rbx
                rcx = 0x1D1851B850F75A3;                //mov rcx, 0x1D1851B850F75A3
                rax *= rcx;             //imul rax, rcx
                rax -= rbx;             //sub rax, rbx
                return rax;
        }
        case 13:
        {
                r10 = p_mem.read64(st::module_base + 0xB34D124);                //mov r10, [0x0000000008166AE6]
                r11 = st::module_base + 0x890E;                 //lea r11, [0xFFFFFFFFFCE222BD]
                rcx = rax;              //mov rcx, rax
                rcx >>= 0xE;            //shr rcx, 0x0E
                rdx = rdi;              //mov rdx, rdi
                rax ^= rcx;             //xor rax, rcx
                rcx = rax;              //mov rcx, rax
                rdx -= r11;             //sub rdx, r11
                rcx >>= 0x1C;           //shr rcx, 0x1C
                rax ^= rcx;             //xor rax, rcx
                rcx = rax;              //mov rcx, rax
                rcx >>= 0x38;           //shr rcx, 0x38
                rdx ^= rcx;             //xor rdx, rcx
                rax ^= rdx;             //xor rax, rdx
                rcx = rax;              //mov rcx, rax
                rcx >>= 0x1D;           //shr rcx, 0x1D
                rax ^= rcx;             //xor rax, rcx
                rdx = 0;                //and rdx, 0xFFFFFFFFC0000000
                rdx = _rotl64(rdx, 0x10);               //rol rdx, 0x10
                rcx = rax;              //mov rcx, rax
                rdx ^= r10;             //xor rdx, r10
                rcx >>= 0x3A;           //shr rcx, 0x3A
                rdx = _byteswap_uint64(rdx);            //bswap rdx
                rax ^= rcx;             //xor rax, rcx
                rax *= p_mem.read64(rdx + 0xb);                 //imul rax, [rdx+0x0B]
                rcx = 0xF9535E8ED75E6455;               //mov rcx, 0xF9535E8ED75E6455
                rax *= rcx;             //imul rax, rcx
                rax ^= rdi;             //xor rax, rdi
                rcx = 0xD5FB51EB4E43F512;               //mov rcx, 0xD5FB51EB4E43F512
                rax ^= rcx;             //xor rax, rcx
                rcx = 0x7F9F02CA1DD4987E;               //mov rcx, 0x7F9F02CA1DD4987E
                rax -= rcx;             //sub rax, rcx
                return rax;
        }
        case 14:
        {
                r10 = p_mem.read64(st::module_base + 0xB34D124);                //mov r10, [0x0000000008166713]
                rbx = st::module_base + 0xCE4D;                 //lea rbx, [0xFFFFFFFFFCE26429]
                rcx = rax;              //mov rcx, rax
                rcx >>= 0x1E;           //shr rcx, 0x1E
                rax ^= rcx;             //xor rax, rcx
                rcx = rax;              //mov rcx, rax
                rcx >>= 0x3C;           //shr rcx, 0x3C
                rax ^= rcx;             //xor rax, rcx
                rcx = 0x842E0BB61A5EF5DF;               //mov rcx, 0x842E0BB61A5EF5DF
                rax *= rcx;             //imul rax, rcx
                rdx = st::module_base + 0x2FDE;                 //lea rdx, [0xFFFFFFFFFCE1C422]
                rdx = ~rdx;             //not rdx
                rcx = rdi;              //mov rcx, rdi
                rcx = ~rcx;             //not rcx
                rdx += rcx;             //add rdx, rcx
                rcx = 0x3ED67BBA1A225257;               //mov rcx, 0x3ED67BBA1A225257
                rax ^= rdx;             //xor rax, rdx
                rax *= rcx;             //imul rax, rcx
                rcx = rbx;              //mov rcx, rbx
                rcx = ~rcx;             //not rcx
                rcx -= rdi;             //sub rcx, rdi
                rax += rcx;             //add rax, rcx
                rax ^= rdi;             //xor rax, rdi
                rcx = 0x7BBC90CAC1A30E69;               //mov rcx, 0x7BBC90CAC1A30E69
                rax *= rcx;             //imul rax, rcx
                rcx = 0;                //and rcx, 0xFFFFFFFFC0000000
                rcx = _rotl64(rcx, 0x10);               //rol rcx, 0x10
                rcx ^= r10;             //xor rcx, r10
                rcx = _byteswap_uint64(rcx);            //bswap rcx
                rax *= p_mem.read64(rcx + 0xb);                 //imul rax, [rcx+0x0B]
                return rax;
        }
        case 15:
        {
                r10 = p_mem.read64(st::module_base + 0xB34D124);                //mov r10, [0x0000000008166179]
                rbx = st::module_base;          //lea rbx, [0xFFFFFFFFFCE1904E]
                r15 = 0x3FB8183AB5CA329A;               //mov r15, 0x3FB8183AB5CA329A
                rcx = rax;              //mov rcx, rax
                rcx >>= 0x7;            //shr rcx, 0x07
                rax ^= rcx;             //xor rax, rcx
                rcx = rax;              //mov rcx, rax
                rcx >>= 0xE;            //shr rcx, 0x0E
                rax ^= rcx;             //xor rax, rcx
                rcx = rax;              //mov rcx, rax
                rcx >>= 0x1C;           //shr rcx, 0x1C
                rax ^= rcx;             //xor rax, rcx
                rcx = rax;              //mov rcx, rax
                rcx >>= 0x38;           //shr rcx, 0x38
                rax ^= rcx;             //xor rax, rcx
                rcx = 0xFFFFFFFFFFFF6142;               //mov rcx, 0xFFFFFFFFFFFF6142
                rcx -= rdi;             //sub rcx, rdi
                rcx -= rbx;             //sub rcx, rbx
                rax += rcx;             //add rax, rcx
                rax ^= rbx;             //xor rax, rbx
                rcx = 0;                //and rcx, 0xFFFFFFFFC0000000
                rcx = _rotl64(rcx, 0x10);               //rol rcx, 0x10
                rcx ^= r10;             //xor rcx, r10
                rcx = _byteswap_uint64(rcx);            //bswap rcx
                rax *= p_mem.read64(rcx + 0xb);                 //imul rax, [rcx+0x0B]
                rax += r15;             //add rax, r15
                rcx = st::module_base + 0x3582E417;             //lea rcx, [0x000000003264722B]
                rcx -= rdi;             //sub rcx, rdi
                rax += rcx;             //add rax, rcx
                rcx = 0x832534D07710273F;               //mov rcx, 0x832534D07710273F
                rax *= rcx;             //imul rax, rcx
                rcx = 0x454E739CB6009B69;               //mov rcx, 0x454E739CB6009B69
                rax ^= rcx;             //xor rax, rcx
                return rax;
        }
        }
};
 
uintptr_t get_bone_index(uint32_t bone_index)
{
        uint64_t mb = st::module_base;
        uint64_t rax = mb, rbx = mb, rcx = mb, rdx = mb, rdi = mb, rsi = mb, r8 = mb, r9 = mb, r10 = mb, r11 = mb, r12 = mb, r13 = mb, r14 = mb, r15 = mb;
 
        rsi = bone_index;
        rcx = rsi * 0x13C8;
        rax = 0xCC70CD3D3E0A7B49;               //mov rax, 0xCC70CD3D3E0A7B49
        rax = _umul128(rax, rcx, (uintptr_t*)&rdx);             //mul rcx
        r11 = st::module_base;          //lea r11, [0xFFFFFFFFFDE2E579]
        r10 = 0x45F86A52798F52B7;               //mov r10, 0x45F86A52798F52B7
        rdx >>= 0xC;            //shr rdx, 0x0C
        rax = rdx * 0x1409;             //imul rax, rdx, 0x1409
        rcx -= rax;             //sub rcx, rax
        rax = 0xDC9D0ECFCB6E9379;               //mov rax, 0xDC9D0ECFCB6E9379
        r8 = rcx * 0x1409;              //imul r8, rcx, 0x1409
        rax = _umul128(rax, r8, (uintptr_t*)&rdx);              //mul r8
        rdx >>= 0xD;            //shr rdx, 0x0D
        rax = rdx * 0x2522;             //imul rax, rdx, 0x2522
        r8 -= rax;              //sub r8, rax
        rax = 0x49539E3B2D066EA3;               //mov rax, 0x49539E3B2D066EA3
        rax = _umul128(rax, r8, (uintptr_t*)&rdx);              //mul r8
        rax = r8;               //mov rax, r8
        rax -= rdx;             //sub rax, rdx
        rax >>= 0x1;            //shr rax, 0x01
        rax += rdx;             //add rax, rdx
        rax >>= 0x9;            //shr rax, 0x09
        rcx = rax * 0x31C;              //imul rcx, rax, 0x31C
        rax = 0xD79435E50D79435F;               //mov rax, 0xD79435E50D79435F
        rax = _umul128(rax, r8, (uintptr_t*)&rdx);              //mul r8
        rdx >>= 0x4;            //shr rdx, 0x04
        rcx += rdx;             //add rcx, rdx
        rax = rcx * 0x26;               //imul rax, rcx, 0x26
        rcx = r8 + r8 * 4;              //lea rcx, [r8+r8*4]
        rcx <<= 0x3;            //shl rcx, 0x03
        rcx -= rax;             //sub rcx, rax
        rax = p_mem.read<uint16_t>(rcx + r11 * 1 + 0xB39D2A0);          //movzx eax, word ptr [rcx+r11*1+0xB39D2A0]
        r8 = rax * 0x13C8;              //imul r8, rax, 0x13C8
        rax = r10;              //mov rax, r10
        rax = _umul128(rax, r8, (uintptr_t*)&rdx);              //mul r8
        rax = r10;              //mov rax, r10
        rdx >>= 0xB;            //shr rdx, 0x0B
        rcx = rdx * 0x1D45;             //imul rcx, rdx, 0x1D45
        r8 -= rcx;              //sub r8, rcx
        r9 = r8 * 0x39A6;               //imul r9, r8, 0x39A6
        rax = _umul128(rax, r9, (uintptr_t*)&rdx);              //mul r9
        rdx >>= 0xB;            //shr rdx, 0x0B
        rax = rdx * 0x1D45;             //imul rax, rdx, 0x1D45
        r9 -= rax;              //sub r9, rax
        rax = 0x88ECF206D1CD0DD7;               //mov rax, 0x88ECF206D1CD0DD7
        rax = _umul128(rax, r9, (uintptr_t*)&rdx);              //mul r9
        rax = 0xAAAAAAAAAAAAAAAB;               //mov rax, 0xAAAAAAAAAAAAAAAB
        rdx >>= 0xB;            //shr rdx, 0x0B
        rcx = rdx * 0xEF5;              //imul rcx, rdx, 0xEF5
        rax = _umul128(rax, r9, (uintptr_t*)&rdx);              //mul r9
        rdx >>= 0x1;            //shr rdx, 0x01
        rcx += rdx;             //add rcx, rdx
        rax = rcx + rcx * 2;            //lea rax, [rcx+rcx*2]
        rax += rax;             //add rax, rax
        rcx = r9 * 8 + 0x0;             //lea rcx, [r9*8]
        rcx -= rax;             //sub rcx, rax
        r15 = p_mem.read<uint16_t>(rcx + r11 * 1 + 0xB3A48D0);          //movsx r15d, word ptr [rcx+r11*1+0xB3A48D0]
        return r15;
};
 
uintptr_t decrypt_bone_base()
{
        uint64_t mb = st::module_base;
        uint64_t rax = mb, rbx = mb, rcx = mb, rdx = mb, rdi = mb, rsi = mb, r8 = mb, r9 = mb, r10 = mb, r11 = mb, r12 = mb, r13 = mb, r14 = mb, r15 = mb;
 
        r8 = p_mem.read64(st::module_base + 0x1119A660);
        if(!r8)
                return r8;
 
        rbx = st::peb;          //mov rbx, gs:[rax]
        //failed to translate: jz 0x0000000000004810
        rax = rbx;              //mov rax, rbx
        rax = _rotl64(rax, 0x2D);               //rol rax, 0x2D
        rax &= 0xF;
 
        switch(rax)
        {
        case 0:
        {
                r9 = p_mem.read64(st::module_base + 0xB34D1F5);                 //mov r9, [0x0000000007877AD6]
                rsi = st::module_base + 0xB6EA;                 //lea rsi, [0xFFFFFFFFFC535FC4]
                rax = r8;               //mov rax, r8
                rax >>= 0x28;           //shr rax, 0x28
                r8 ^= rax;              //xor r8, rax
                rax = rbx;              //mov rax, rbx
                rax *= rsi;             //imul rax, rsi
                r8 -= rax;              //sub r8, rax
                rax = r8;               //mov rax, r8
                rax >>= 0xC;            //shr rax, 0x0C
                r8 ^= rax;              //xor r8, rax
                rax = r8;               //mov rax, r8
                rax >>= 0x18;           //shr rax, 0x18
                r8 ^= rax;              //xor r8, rax
                rax = r8;               //mov rax, r8
                rax >>= 0x30;           //shr rax, 0x30
                r8 ^= rax;              //xor r8, rax
                rax = 0xDB337DD153DA0B8C;               //mov rax, 0xDB337DD153DA0B8C
                r8 ^= rax;              //xor r8, rax
                rax = 0xEE0CA2455E5A4431;               //mov rax, 0xEE0CA2455E5A4431
                r8 *= rax;              //imul r8, rax
                r8 += rbx;              //add r8, rbx
                rax = 0;                //and rax, 0xFFFFFFFFC0000000
                rax = _rotl64(rax, 0x10);               //rol rax, 0x10
                rax ^= r9;              //xor rax, r9
                rax = ~rax;             //not rax
                rax = p_mem.read64(rax + 0xb);          //mov rax, [rax+0x0B]
                uintptr_t RSP_0x70;
                RSP_0x70 = 0xC14865206AF3F8BD;          //mov rax, 0xC14865206AF3F8BD : RSP+0x70
                rax *= RSP_0x70;                //imul rax, [rsp+0x70]
                r8 *= rax;              //imul r8, rax
                return r8;
        }
        case 1:
        {
                r10 = p_mem.read64(st::module_base + 0xB34D1F5);                //mov r10, [0x0000000007877642]
                r11 = st::module_base;          //lea r11, [0xFFFFFFFFFC52A43A]
                rax = st::module_base + 0x7A19AFE1;             //lea rax, [0x00000000766C5215]
                rax -= rbx;             //sub rax, rbx
                r8 += rax;              //add r8, rax
                rax = r8;               //mov rax, r8
                rax >>= 0x16;           //shr rax, 0x16
                r8 ^= rax;              //xor r8, rax
                rax = r8;               //mov rax, r8
                rax >>= 0x2C;           //shr rax, 0x2C
                r8 ^= rax;              //xor r8, rax
                r8 += rbx;              //add r8, rbx
                rax = r11 + 0x6948;             //lea rax, [r11+0x6948]
                rax += rbx;             //add rax, rbx
                r8 ^= rax;              //xor r8, rax
                rax = 0x15072D5109A87A59;               //mov rax, 0x15072D5109A87A59
                r8 += rax;              //add r8, rax
                rax = 0xF757FE5164B68C93;               //mov rax, 0xF757FE5164B68C93
                r8 *= rax;              //imul r8, rax
                rax = 0;                //and rax, 0xFFFFFFFFC0000000
                rax = _rotl64(rax, 0x10);               //rol rax, 0x10
                rax ^= r10;             //xor rax, r10
                rax = ~rax;             //not rax
                r8 *= p_mem.read64(rax + 0xb);          //imul r8, [rax+0x0B]
                rax = 0x2FB01E75992D9EA9;               //mov rax, 0x2FB01E75992D9EA9
                r8 ^= rax;              //xor r8, rax
                return r8;
        }
        case 2:
        {
                r10 = p_mem.read64(st::module_base + 0xB34D1F5);                //mov r10, [0x0000000007877166]
                r11 = st::module_base;          //lea r11, [0xFFFFFFFFFC529F5E]
                rax = 0xEC872CF509395FFD;               //mov rax, 0xEC872CF509395FFD
                r8 ^= rax;              //xor r8, rax
                rax = r8;               //mov rax, r8
                rax >>= 0x24;           //shr rax, 0x24
                r8 ^= rax;              //xor r8, rax
                r8 -= r11;              //sub r8, r11
                rax = 0x667BD9DAEABF22FD;               //mov rax, 0x667BD9DAEABF22FD
                r8 *= rax;              //imul r8, rax
                r8 = r8 + rbx * 2;              //lea r8, [r8+rbx*2]
                r8 ^= rbx;              //xor r8, rbx
                rax = 0;                //and rax, 0xFFFFFFFFC0000000
                rax = _rotl64(rax, 0x10);               //rol rax, 0x10
                rax ^= r10;             //xor rax, r10
                rax = ~rax;             //not rax
                r8 *= p_mem.read64(rax + 0xb);          //imul r8, [rax+0x0B]
                return r8;
        }
        case 3:
        {
                r10 = p_mem.read64(st::module_base + 0xB34D1F5);                //mov r10, [0x0000000007876D92]
                rax = 0x37EBC051754B4857;               //mov rax, 0x37EBC051754B4857
                r8 *= rax;              //imul r8, rax
                rax = 0;                //and rax, 0xFFFFFFFFC0000000
                rax = _rotl64(rax, 0x10);               //rol rax, 0x10
                rax ^= r10;             //xor rax, r10
                rax = ~rax;             //not rax
                r8 *= p_mem.read64(rax + 0xb);          //imul r8, [rax+0x0B]
                rax = 0x9922118D8E05DB98;               //mov rax, 0x9922118D8E05DB98
                r8 ^= rax;              //xor r8, rax
                rax = r8;               //mov rax, r8
                rax >>= 0x19;           //shr rax, 0x19
                r8 ^= rax;              //xor r8, rax
                rax = r8;               //mov rax, r8
                rax >>= 0x32;           //shr rax, 0x32
                r8 ^= rax;              //xor r8, rax
                rax = 0x865261C07421C221;               //mov rax, 0x865261C07421C221
                r8 *= rax;              //imul r8, rax
                rax = st::module_base + 0x66E268BC;             //lea rax, [0x0000000063350330]
                rax -= rbx;             //sub rax, rbx
                r8 += rax;              //add r8, rax
                rax = r8;               //mov rax, r8
                rax >>= 0x12;           //shr rax, 0x12
                r8 ^= rax;              //xor r8, rax
                rcx = r8;               //mov rcx, r8
                rcx >>= 0x24;           //shr rcx, 0x24
                rcx ^= r8;              //xor rcx, r8
                rax = rbx + 0x1;                //lea rax, [rbx+0x01]
                r8 = st::module_base + 0xF277;          //lea r8, [0xFFFFFFFFFC538A99]
                r8 *= rax;              //imul r8, rax
                r8 += rcx;              //add r8, rcx
                return r8;
        }
        case 4:
        {
                r11 = p_mem.read64(st::module_base + 0xB34D1F5);                //mov r11, [0x00000000078768D6]
                rcx = st::module_base + 0x7A9601A5;             //lea rcx, [0x0000000076E8980F]
                rax = rbx;              //mov rax, rbx
                rax *= rcx;             //imul rax, rcx
                r8 -= rax;              //sub r8, rax
                rax = 0xCD112C2E06C18F97;               //mov rax, 0xCD112C2E06C18F97
                r8 ^= rbx;              //xor r8, rbx
                r8 *= rax;              //imul r8, rax
                rax = 0x5D25C543C2A3275E;               //mov rax, 0x5D25C543C2A3275E
                r8 += rax;              //add r8, rax
                rax = r8;               //mov rax, r8
                rax >>= 0xE;            //shr rax, 0x0E
                r8 ^= rax;              //xor r8, rax
                rax = r8;               //mov rax, r8
                rax >>= 0x1C;           //shr rax, 0x1C
                r8 ^= rax;              //xor r8, rax
                rcx = rbx;              //mov rcx, rbx
                rcx = ~rcx;             //not rcx
                rax = st::module_base + 0xE971;                 //lea rax, [0xFFFFFFFFFC537DF2]
                rcx += rax;             //add rcx, rax
                rax = r8;               //mov rax, r8
                rdx = 0;                //and rdx, 0xFFFFFFFFC0000000
                rax >>= 0x38;           //shr rax, 0x38
                rdx = _rotl64(rdx, 0x10);               //rol rdx, 0x10
                rcx ^= rax;             //xor rcx, rax
                rdx ^= r11;             //xor rdx, r11
                r8 ^= rcx;              //xor r8, rcx
                rdx = ~rdx;             //not rdx
                r8 *= p_mem.read64(rdx + 0xb);          //imul r8, [rdx+0x0B]
                rax = 0xEA03A4029DA296DB;               //mov rax, 0xEA03A4029DA296DB
                r8 *= rax;              //imul r8, rax
                return r8;
        }
        case 5:
        {
                r9 = p_mem.read64(st::module_base + 0xB34D1F5);                 //mov r9, [0x0000000007876528]
                r11 = st::module_base;          //lea r11, [0xFFFFFFFFFC529320]
                rax = r11 + 0x49f56405;                 //lea rax, [r11+0x49F56405]
                rax += rbx;             //add rax, rbx
                r8 ^= rax;              //xor r8, rax
                r8 -= r11;              //sub r8, r11
                rax = 0x23E90120D3B246A9;               //mov rax, 0x23E90120D3B246A9
                r8 *= rax;              //imul r8, rax
                rax = r8;               //mov rax, r8
                rax >>= 0x16;           //shr rax, 0x16
                r8 ^= rax;              //xor r8, rax
                rax = r8;               //mov rax, r8
                rax >>= 0x2C;           //shr rax, 0x2C
                r8 ^= rax;              //xor r8, rax
                rax = 0;                //and rax, 0xFFFFFFFFC0000000
                rax = _rotl64(rax, 0x10);               //rol rax, 0x10
                rax ^= r9;              //xor rax, r9
                rax = ~rax;             //not rax
                rax = p_mem.read64(rax + 0xb);          //mov rax, [rax+0x0B]
                uintptr_t RSP_0x60;
                RSP_0x60 = 0x3DD6F27815FF4CC7;          //mov rax, 0x3DD6F27815FF4CC7 : RSP+0x60
                rax *= RSP_0x60;                //imul rax, [rsp+0x60]
                r8 *= rax;              //imul r8, rax
                r8 -= rbx;              //sub r8, rbx
                rax = r8;               //mov rax, r8
                rax >>= 0x26;           //shr rax, 0x26
                r8 ^= rax;              //xor r8, rax
                return r8;
        }
        case 6:
        {
                r10 = p_mem.read64(st::module_base + 0xB34D1F5);                //mov r10, [0x00000000078760D6]
                r11 = st::module_base;          //lea r11, [0xFFFFFFFFFC528ECE]
                rax = 0xD60BA9D95062B96B;               //mov rax, 0xD60BA9D95062B96B
                r8 *= rax;              //imul r8, rax
                rax = rbx;              //mov rax, rbx
                rax -= r11;             //sub rax, r11
                rax += 0xFFFFFFFFB3C78361;              //add rax, 0xFFFFFFFFB3C78361
                r8 += rax;              //add r8, rax
                rcx = st::module_base + 0xB4F3;                 //lea rcx, [0xFFFFFFFFFC5342E1]
                rcx = ~rcx;             //not rcx
                rcx ^= rbx;             //xor rcx, rbx
                rax = st::module_base + 0x6AA;          //lea rax, [0xFFFFFFFFFC529486]
                rax = ~rax;             //not rax
                rax -= rcx;             //sub rax, rcx
                rax -= rbx;             //sub rax, rbx
                r8 += rax;              //add r8, rax
                rax = 0;                //and rax, 0xFFFFFFFFC0000000
                rax = _rotl64(rax, 0x10);               //rol rax, 0x10
                rax ^= r10;             //xor rax, r10
                rax = ~rax;             //not rax
                r8 *= p_mem.read64(rax + 0xb);          //imul r8, [rax+0x0B]
                r8 ^= r11;              //xor r8, r11
                rax = r8;               //mov rax, r8
                rax >>= 0xE;            //shr rax, 0x0E
                r8 ^= rax;              //xor r8, rax
                rax = r8;               //mov rax, r8
                rax >>= 0x1C;           //shr rax, 0x1C
                r8 ^= rax;              //xor r8, rax
                rax = r8;               //mov rax, r8
                rax >>= 0x38;           //shr rax, 0x38
                r8 ^= rax;              //xor r8, rax
                rax = r8;               //mov rax, r8
                rax >>= 0x4;            //shr rax, 0x04
                r8 ^= rax;              //xor r8, rax
                rax = r8;               //mov rax, r8
                rax >>= 0x8;            //shr rax, 0x08
                r8 ^= rax;              //xor r8, rax
                rax = r8;               //mov rax, r8
                rax >>= 0x10;           //shr rax, 0x10
                r8 ^= rax;              //xor r8, rax
                rax = r8;               //mov rax, r8
                rax >>= 0x20;           //shr rax, 0x20
                r8 ^= rax;              //xor r8, rax
                return r8;
        }
        case 7:
        {
                r9 = p_mem.read64(st::module_base + 0xB34D1F5);                 //mov r9, [0x0000000007875BBE]
                r11 = st::module_base;          //lea r11, [0xFFFFFFFFFC5289B1]
                r8 ^= rbx;              //xor r8, rbx
                rax = r8;               //mov rax, r8
                rax >>= 0x10;           //shr rax, 0x10
                r8 ^= rax;              //xor r8, rax
                rax = r8;               //mov rax, r8
                rax >>= 0x20;           //shr rax, 0x20
                r8 ^= rax;              //xor r8, rax
                rax = 0xEC3F2E44438C40E1;               //mov rax, 0xEC3F2E44438C40E1
                r8 *= rax;              //imul r8, rax
                rax = 0x46C9BFC3207FE432;               //mov rax, 0x46C9BFC3207FE432
                r8 ^= rax;              //xor r8, rax
                rax = r8;               //mov rax, r8
                rax >>= 0x15;           //shr rax, 0x15
                r8 ^= rax;              //xor r8, rax
                rax = r8;               //mov rax, r8
                rax >>= 0x2A;           //shr rax, 0x2A
                r8 ^= rax;              //xor r8, rax
                r8 -= r11;              //sub r8, r11
                rax = 0;                //and rax, 0xFFFFFFFFC0000000
                rax = _rotl64(rax, 0x10);               //rol rax, 0x10
                rax ^= r9;              //xor rax, r9
                rax = ~rax;             //not rax
                r8 *= p_mem.read64(rax + 0xb);          //imul r8, [rax+0x0B]
                rax = 0x12B613C3932D6D9E;               //mov rax, 0x12B613C3932D6D9E
                r8 += rax;              //add r8, rax
                return r8;
        }
        case 8:
        {
                r10 = p_mem.read64(st::module_base + 0xB34D1F5);                //mov r10, [0x000000000787572F]
                r11 = st::module_base;          //lea r11, [0xFFFFFFFFFC52851B]
                rax = 0x5C5F32091DD159B1;               //mov rax, 0x5C5F32091DD159B1
                r8 *= rax;              //imul r8, rax
                r8 -= rbx;              //sub r8, rbx
                r8 -= r11;              //sub r8, r11
                r8 -= 0xF6CE;           //sub r8, 0xF6CE
                rax = 0x3D82E67B9C690D82;               //mov rax, 0x3D82E67B9C690D82
                r8 += rax;              //add r8, rax
                rax = r8;               //mov rax, r8
                rax >>= 0x7;            //shr rax, 0x07
                r8 ^= rax;              //xor r8, rax
                rax = r8;               //mov rax, r8
                rax >>= 0xE;            //shr rax, 0x0E
                r8 ^= rax;              //xor r8, rax
                rax = r8;               //mov rax, r8
                rax >>= 0x1C;           //shr rax, 0x1C
                r8 ^= rax;              //xor r8, rax
                rax = r8;               //mov rax, r8
                rax >>= 0x38;           //shr rax, 0x38
                r8 ^= rax;              //xor r8, rax
                rax = 0x6E6329D1DCD95A8E;               //mov rax, 0x6E6329D1DCD95A8E
                r8 += rax;              //add r8, rax
                rax = rbx;              //mov rax, rbx
                uintptr_t RSP_0x70;
                RSP_0x70 = st::module_base + 0x1296AB18;                //lea rax, [0x000000000EE9304B] : RSP+0x70
                rax ^= RSP_0x70;                //xor rax, [rsp+0x70]
                r8 -= rax;              //sub r8, rax
                rax = 0;                //and rax, 0xFFFFFFFFC0000000
                rax = _rotl64(rax, 0x10);               //rol rax, 0x10
                rax ^= r10;             //xor rax, r10
                rax = ~rax;             //not rax
                r8 *= p_mem.read64(rax + 0xb);          //imul r8, [rax+0x0B]
                r8 += r11;              //add r8, r11
                return r8;
        }
        case 9:
        {
                r10 = p_mem.read64(st::module_base + 0xB34D1F5);                //mov r10, [0x00000000078751BA]
                r11 = st::module_base;          //lea r11, [0xFFFFFFFFFC527FB2]
                rcx = r11 + 0x7653f022;                 //lea rcx, [r11+0x7653F022]
                rcx += rbx;             //add rcx, rbx
                rax = r8;               //mov rax, r8
                rax >>= 0x27;           //shr rax, 0x27
                rcx ^= rax;             //xor rcx, rax
                r8 ^= rcx;              //xor r8, rcx
                rax = 0xE075ACC895E477D5;               //mov rax, 0xE075ACC895E477D5
                r8 *= rax;              //imul r8, rax
                rax = st::module_base + 0x5B7B03DD;             //lea rax, [0x0000000057CD8249]
                r8 -= rbx;              //sub r8, rbx
                r8 += rax;              //add r8, rax
                rax = r8;               //mov rax, r8
                rax >>= 0x10;           //shr rax, 0x10
                r8 ^= rax;              //xor r8, rax
                rax = r8;               //mov rax, r8
                rax >>= 0x20;           //shr rax, 0x20
                r8 ^= rax;              //xor r8, rax
                rcx = 0;                //and rcx, 0xFFFFFFFFC0000000
                rax = r8;               //mov rax, r8
                rcx = _rotl64(rcx, 0x10);               //rol rcx, 0x10
                rax >>= 0x1E;           //shr rax, 0x1E
                rcx ^= r10;             //xor rcx, r10
                r8 ^= rax;              //xor r8, rax
                rcx = ~rcx;             //not rcx
                rax = r8;               //mov rax, r8
                rax >>= 0x3C;           //shr rax, 0x3C
                r8 ^= rax;              //xor r8, rax
                rax = 0xC83A6B65305CE875;               //mov rax, 0xC83A6B65305CE875
                r8 *= p_mem.read64(rcx + 0xb);          //imul r8, [rcx+0x0B]
                r8 *= rax;              //imul r8, rax
                return r8;
        }
        case 10:
        {
                r10 = p_mem.read64(st::module_base + 0xB34D1F5);                //mov r10, [0x0000000007874E2D]
                r11 = st::module_base;          //lea r11, [0xFFFFFFFFFC527C25]
                rax = st::module_base + 0x2505156F;             //lea rax, [0x00000000215790BA]
                rax *= rbx;             //imul rax, rbx
                r8 ^= rax;              //xor r8, rax
                rax = 0x589E1DB58B2CC13;                //mov rax, 0x589E1DB58B2CC13
                r8 *= rax;              //imul r8, rax
                rax = 0xA1E3AB5A718E9853;               //mov rax, 0xA1E3AB5A718E9853
                r8 *= rax;              //imul r8, rax
                r8 += r11;              //add r8, r11
                rax = 0;                //and rax, 0xFFFFFFFFC0000000
                rax = _rotl64(rax, 0x10);               //rol rax, 0x10
                rax ^= r10;             //xor rax, r10
                rax = ~rax;             //not rax
                rax = p_mem.read64(rax + 0xb);          //mov rax, [rax+0x0B]
                uintptr_t RSP_0x58;
                RSP_0x58 = 0x81A05DFC5176F5AB;          //mov rax, 0x81A05DFC5176F5AB : RSP+0x58
                rax *= RSP_0x58;                //imul rax, [rsp+0x58]
                r8 *= rax;              //imul r8, rax
                rax = r8;               //mov rax, r8
                rax >>= 0x10;           //shr rax, 0x10
                r8 ^= rax;              //xor r8, rax
                rax = r8;               //mov rax, r8
                rax >>= 0x20;           //shr rax, 0x20
                r8 ^= rax;              //xor r8, rax
                r8 -= r11;              //sub r8, r11
                return r8;
        }
        case 11:
        {
                r10 = p_mem.read64(st::module_base + 0xB34D1F5);                //mov r10, [0x00000000078749F9]
                r11 = st::module_base;          //lea r11, [0xFFFFFFFFFC5277F1]
                rax = rbx;              //mov rax, rbx
                rax = ~rax;             //not rax
                uintptr_t RSP_0x78;
                RSP_0x78 = st::module_base + 0x211B;            //lea rax, [0xFFFFFFFFFC5298D3] : RSP+0x78
                rax += RSP_0x78;                //add rax, [rsp+0x78]
                r8 ^= rax;              //xor r8, rax
                rax = 0x4707F2F1B7F39AB1;               //mov rax, 0x4707F2F1B7F39AB1
                r8 *= rax;              //imul r8, rax
                rax = 0x4FF5D4D41EB571E1;               //mov rax, 0x4FF5D4D41EB571E1
                r8 -= rax;              //sub r8, rax
                rax = 0xB981AA7ECCD36DA7;               //mov rax, 0xB981AA7ECCD36DA7
                r8 ^= rax;              //xor r8, rax
                r8 += r11;              //add r8, r11
                rax = rbx;              //mov rax, rbx
                rax -= r11;             //sub rax, r11
                rax -= 0x1E624739;              //sub rax, 0x1E624739
                r8 ^= rax;              //xor r8, rax
                rax = r8;               //mov rax, r8
                rax >>= 0x27;           //shr rax, 0x27
                r8 ^= rax;              //xor r8, rax
                rax = 0;                //and rax, 0xFFFFFFFFC0000000
                rax = _rotl64(rax, 0x10);               //rol rax, 0x10
                rax ^= r10;             //xor rax, r10
                rax = ~rax;             //not rax
                r8 *= p_mem.read64(rax + 0xb);          //imul r8, [rax+0x0B]
                return r8;
        }
        case 12:
        {
                r10 = p_mem.read64(st::module_base + 0xB34D1F5);                //mov r10, [0x00000000078744EE]
                rax = 0;                //and rax, 0xFFFFFFFFC0000000
                rax = _rotl64(rax, 0x10);               //rol rax, 0x10
                rax ^= r10;             //xor rax, r10
                rax = ~rax;             //not rax
                r8 *= p_mem.read64(rax + 0xb);          //imul r8, [rax+0x0B]
                rax = 0x150309B26C3600E2;               //mov rax, 0x150309B26C3600E2
                r8 ^= rax;              //xor r8, rax
                rax = 0x9039248D8DECCBD;                //mov rax, 0x9039248D8DECCBD
                r8 *= rax;              //imul r8, rax
                rax = r8;               //mov rax, r8
                rax >>= 0x20;           //shr rax, 0x20
                r8 ^= rax;              //xor r8, rax
                rax = r8;               //mov rax, r8
                rax >>= 0x24;           //shr rax, 0x24
                r8 ^= rax;              //xor r8, rax
                rax = 0x6540FD94DE1D496C;               //mov rax, 0x6540FD94DE1D496C
                r8 += rax;              //add r8, rax
                r8 ^= rbx;              //xor r8, rbx
                rax = r8;               //mov rax, r8
                rax >>= 0x12;           //shr rax, 0x12
                r8 ^= rax;              //xor r8, rax
                rax = r8;               //mov rax, r8
                rax >>= 0x24;           //shr rax, 0x24
                r8 ^= rax;              //xor r8, rax
                return r8;
        }
        case 13:
        {
                r10 = p_mem.read64(st::module_base + 0xB34D1F5);                //mov r10, [0x00000000078740AA]
                r11 = st::module_base;          //lea r11, [0xFFFFFFFFFC526EA2]
                r8 ^= r11;              //xor r8, r11
                rax = r8;               //mov rax, r8
                rax >>= 0x1B;           //shr rax, 0x1B
                r8 ^= rax;              //xor r8, rax
                rax = r8;               //mov rax, r8
                rax >>= 0x36;           //shr rax, 0x36
                r8 ^= rax;              //xor r8, rax
                rax = st::module_base + 0x55D7115D;             //lea rax, [0x0000000052297EC1]
                rax += rbx;             //add rax, rbx
                r8 ^= rax;              //xor r8, rax
                r8 ^= rbx;              //xor r8, rbx
                r8 ^= rbx;              //xor r8, rbx
                rcx = 0;                //and rcx, 0xFFFFFFFFC0000000
                rcx = _rotl64(rcx, 0x10);               //rol rcx, 0x10
                rcx ^= r10;             //xor rcx, r10
                rcx = ~rcx;             //not rcx
                r8 *= p_mem.read64(rcx + 0xb);          //imul r8, [rcx+0x0B]
                rax = 0x6F99F051FEABC21E;               //mov rax, 0x6F99F051FEABC21E
                r8 += rax;              //add r8, rax
                rax = 0x90249100C816A8E3;               //mov rax, 0x90249100C816A8E3
                r8 *= rax;              //imul r8, rax
                return r8;
        }
        case 14:
        {
                r10 = p_mem.read64(st::module_base + 0xB34D1F5);                //mov r10, [0x0000000007873BFE]
                rax = 0x77076EC329271D9F;               //mov rax, 0x77076EC329271D9F
                r8 *= rax;              //imul r8, rax
                rcx = 0x1;              //mov ecx, 0x01
                rax = st::module_base + 0x625A6658;             //lea rax, [0x000000005EACCE98]
                rcx -= rax;             //sub rcx, rax
                rax = st::module_base + 0x1D71A0DE;             //lea rax, [0x0000000019C40914]
                r8 += rax;              //add r8, rax
                rcx *= rbx;             //imul rcx, rbx
                r8 += rcx;              //add r8, rcx
                rax = 0x7BD234C2F4D59D11;               //mov rax, 0x7BD234C2F4D59D11
                r8 ^= rax;              //xor r8, rax
                rax = 0x9FA21223F8F4EBD9;               //mov rax, 0x9FA21223F8F4EBD9
                r8 *= rax;              //imul r8, rax
                rax = r8;               //mov rax, r8
                rax >>= 0x13;           //shr rax, 0x13
                r8 ^= rax;              //xor r8, rax
                rax = r8;               //mov rax, r8
                rax >>= 0x26;           //shr rax, 0x26
                r8 ^= rax;              //xor r8, rax
                rcx = 0;                //and rcx, 0xFFFFFFFFC0000000
                rcx = _rotl64(rcx, 0x10);               //rol rcx, 0x10
                rcx ^= r10;             //xor rcx, r10
                rax = st::module_base + 0xF292;                 //lea rax, [0xFFFFFFFFFC535A0C]
                rax *= rbx;             //imul rax, rbx
                rcx = ~rcx;             //not rcx
                r8 += rax;              //add r8, rax
                r8 *= p_mem.read64(rcx + 0xb);          //imul r8, [rcx+0x0B]
                return r8;
        }
        case 15:
        {
                r10 = p_mem.read64(st::module_base + 0xB34D1F5);                //mov r10, [0x000000000787371E]
                r11 = st::module_base;          //lea r11, [0xFFFFFFFFFC526516]
                rax = r8;               //mov rax, r8
                rax >>= 0x1F;           //shr rax, 0x1F
                r8 ^= rax;              //xor r8, rax
                rax = r8;               //mov rax, r8
                rax >>= 0x3E;           //shr rax, 0x3E
                r8 ^= rax;              //xor r8, rax
                rax = r8;               //mov rax, r8
                rax >>= 0xF;            //shr rax, 0x0F
                r8 ^= rax;              //xor r8, rax
                rax = r8;               //mov rax, r8
                rax >>= 0x1E;           //shr rax, 0x1E
                r8 ^= rax;              //xor r8, rax
                rax = r8;               //mov rax, r8
                rax >>= 0x3C;           //shr rax, 0x3C
                r8 ^= rax;              //xor r8, rax
                rcx = 0;                //and rcx, 0xFFFFFFFFC0000000
                rax = r8;               //mov rax, r8
                rcx = _rotl64(rcx, 0x10);               //rol rcx, 0x10
                rcx ^= r10;             //xor rcx, r10
                rax >>= 0x20;           //shr rax, 0x20
                r8 ^= rax;              //xor r8, rax
                rcx = ~rcx;             //not rcx
                r8 *= p_mem.read64(rcx + 0xb);          //imul r8, [rcx+0x0B]
                r8 -= r11;              //sub r8, r11
                rax = 0x1C1184DB9253F8DB;               //mov rax, 0x1C1184DB9253F8DB
                r8 *= rax;              //imul r8, rax
                r8 -= rbx;              //sub r8, rbx
                return r8;
        }
        }
};
