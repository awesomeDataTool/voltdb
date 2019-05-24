/* This file is part of VoltDB.
 * Copyright (C) 2008-2019 VoltDB Inc.
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

package org.voltcore.utils.ssl;

import java.nio.ByteBuffer;
import java.nio.ReadOnlyBufferException;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLSession;

import org.voltcore.network.TLSException;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.ByteBufAllocator;
import io.netty.buffer.Unpooled;

public class SSLBufferEncrypter {

    private final SSLEngine m_sslEngine;

    public SSLBufferEncrypter(SSLEngine sslEngine) {
        this.m_sslEngine = sslEngine;
    }

    public ByteBuf tlswrap(ByteBuffer src, ByteBufAllocator allocator) {
        ByteBuf encrypted = tlswrap(Unpooled.wrappedBuffer(src), allocator);
        src.position(src.limit());
        return encrypted;
    }

    public ByteBuf tlswrap(ByteBuf src, ByteBufAllocator allocator) {
        SSLSession session = m_sslEngine.getSession();
        int packetBufferSize = session.getPacketBufferSize();
        int applicationBufferSize = session.getApplicationBufferSize();
        int maxEncryptedSize = ((src.readableBytes() + applicationBufferSize - 1) / applicationBufferSize)
                * packetBufferSize;

        ByteBuf dest = allocator.buffer(maxEncryptedSize);

        try {
            assert dest.nioBufferCount() == 1 : "Should only have one buffer: " + dest.nioBufferCount();
            ByteBuffer destNioBuf = dest.nioBuffer(dest.writerIndex(), dest.writableBytes());

            ByteBuffer[] srcNioBuffers = src.nioBuffers();
            do {
                SSLEngineResult result = null;
                try {
                    result = m_sslEngine.wrap(srcNioBuffers, destNioBuf);
                } catch (SSLException | ReadOnlyBufferException | IllegalArgumentException | IllegalStateException e) {
                    throw new TLSException("ssl engine wrap fault", e);
                }
                switch (result.getStatus()) {
                case OK:
                    src.readerIndex(src.readerIndex() + result.bytesConsumed());
                    break;
                case BUFFER_OVERFLOW:
                    throw new TLSException("SSL engine unexpectedly overflowed when enrypting");
                case BUFFER_UNDERFLOW:
                    throw new TLSException("SSL engine unexpectedly underflowed when encrypting");
                case CLOSED:
                    throw new TLSException("SSL engine is closed on ssl wrap of buffer.");
                }
            } while (src.isReadable());

            dest.writerIndex(destNioBuf.position());
            return dest;
        } catch (Throwable t) {
            dest.release();
            throw t;
        }
    }
}
