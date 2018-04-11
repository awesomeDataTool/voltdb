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

package org.voltdb.exceptions;

import com.google_voltpatches.common.collect.Maps;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * This exception is used in IV2 MPI repair to terminate the currently running
 * MP transaction at the MPI.  We have a separate exception type so that we can
 * use that to create a unique ClientResponse status so that the running
 * procedure can determine whether or not it is being restarted or whether it
 * completed successfully.
 */
public class TransactionMisroutedException extends SerializableException {
    public static final long serialVersionUID = 0L;
    private long m_txnId;
    public TransactionMisroutedException(String message, long txnId) {
        super(message);
        m_txnId = txnId;
    }

    public TransactionMisroutedException(ByteBuffer b) {
        super(b);
        m_txnId = b.getLong();
    }

    public long getTxnId()
    {
        return m_txnId;
    }

    @Override
    protected SerializableExceptions getExceptionType() {
        return SerializableExceptions.TransactionMisroutedException;
    }

    @Override
    protected int p_getSerializedSize() {
        return 8;
    }

    @Override
    protected void p_serializeToBuffer(ByteBuffer b) {
        b.putLong(m_txnId);
    }
}