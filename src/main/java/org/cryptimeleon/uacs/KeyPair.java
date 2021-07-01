package org.cryptimeleon.uacs;

import org.cryptimeleon.craco.protocols.SecretInput;

public class KeyPair <PK, SK> {
    public final PK pk;
    public final SK sk;

    public KeyPair(PK pk, SK sk) {
        this.pk = pk;
        this.sk = sk;
    }
}
