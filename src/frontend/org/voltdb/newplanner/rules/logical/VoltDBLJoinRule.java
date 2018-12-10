/* This file is part of VoltDB.
 * Copyright (C) 2008-2018 VoltDB Inc.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with VoltDB.  If not, see <http://www.gnu.org/licenses/>.
 */

package org.voltdb.newplanner.rules.logical;

import com.google.common.collect.ImmutableList;
import org.apache.calcite.plan.Convention;
import org.apache.calcite.plan.RelOptRule;
import org.apache.calcite.plan.RelOptRuleCall;
import org.apache.calcite.plan.RelTraitSet;
import org.apache.calcite.rel.RelNode;
import org.apache.calcite.rel.logical.LogicalJoin;
import org.apache.calcite.rel.type.RelDataTypeField;
import org.voltdb.calciteadapter.rel.logical.VoltDBLJoin;
import org.voltdb.calciteadapter.rel.logical.VoltDBLRel;

/**
 * VoltDB logical rule that transform {@link LogicalJoin} to {@link VoltDBLJoin}.
 *
 * @author Chao Zhou
 * @since 8.4
 */
public class VoltDBLJoinRule extends RelOptRule {
    public static final VoltDBLJoinRule INSTANCE = new VoltDBLJoinRule();

    VoltDBLJoinRule() {
        super(operand(LogicalJoin.class, Convention.NONE, any()));
    }

    @Override
    public void onMatch(RelOptRuleCall call) {
        LogicalJoin join = call.rel(0);
        RelNode left = join.getLeft();
        RelNode right = join.getRight();
        RelTraitSet convertedTraits = join.getTraitSet().replace(VoltDBLRel.VOLTDB_LOGICAL);
        RelNode convertedLeft = convert(left, left.getTraitSet().replace(VoltDBLRel.VOLTDB_LOGICAL));
        RelNode convertedRight = convert(right, right.getTraitSet().replace(VoltDBLRel.VOLTDB_LOGICAL));
        ImmutableList<RelDataTypeField> systemFieldList = ImmutableList.copyOf(join.getSystemFieldList());

        call.transformTo(new VoltDBLJoin(join.getCluster(), convertedTraits, convertedLeft, convertedRight,
                join.getCondition(), join.getVariablesSet(), join.getJoinType(),
                join.isSemiJoinDone(), systemFieldList));
    }
}