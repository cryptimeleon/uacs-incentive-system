package org.cryptimeleon.uacs;

import org.cryptimeleon.math.serialization.Representable;
import org.cryptimeleon.math.serialization.Representation;
import org.cryptimeleon.math.serialization.annotations.ReprUtil;
import org.cryptimeleon.math.serialization.annotations.Represented;
import org.cryptimeleon.math.structures.groups.Group;
import org.cryptimeleon.math.structures.groups.GroupElement;
import org.cryptimeleon.math.structures.rings.zn.Zn;

public class DoubleSpendTag implements Representable {
    @Represented(restorer = "zn")
    public Zn.ZnElement c, gamma;
    @Represented(restorer = "G1")
    public GroupElement ctrace0, ctrace1;

    public DoubleSpendTag(Zn.ZnElement c, Zn.ZnElement gamma, GroupElement ctrace0, GroupElement ctrace1) {
        this.c = c;
        this.gamma = gamma;
        this.ctrace0 = ctrace0;
        this.ctrace1 = ctrace1;
    }

    public DoubleSpendTag(Group group, Representation repr) {
        new ReprUtil(this).register(group.getZn(), "zn").register(group, "G1");
    }

    @Override
    public Representation getRepresentation() {
        return ReprUtil.serialize(this);
    }
}
