/* This file is part of VoltDB.
 * Copyright (C) 2008-2013 VoltDB Inc.
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

package org.voltdb.client;

import org.voltdb.VoltTable;

/**
 *  Interface implemented by the responses that are generated for procedure invocations
 */
public interface ClientResponse {
    /**
     * Status code indicating the store procedure executed successfully
     */
    public static final byte SUCCESS = 1;

    /**
     * Status code indicating the stored procedure executed successfully and was voluntarily aborted and rolled
     * back by the stored procedure code
     */
    public static final byte USER_ABORT = -1;

    /**
     * Status code indicating the stored procedure failed and was rolled back. There are no negative server side
     * side effects.
     */
    public static final byte GRACEFUL_FAILURE = -2;

    /**
     * Status code indicating the stored procedure failed (or may never have been successfully invoked)
     * and that there may have been negative side effects on the server
     */
    public static final byte UNEXPECTED_FAILURE = -3;

    /**
     * Status code indicating the connection to the database that the invocation was queued at
     * was lost before a response was received. It is possible that the invocation was sent, executed, and successfully
     * committed before a response could be returned or the invocation may never have been sent.
     */
    public static final byte CONNECTION_LOST = -4;

    /**
     * Status code indicating that the server is currently unavailable for stored procedure invocations.
     * The invocation for which this is a response was never executed.
     */
    public static final byte SERVER_UNAVAILABLE = -5;

    /**
     * Status code indicating that the request didn't receive a response before the per-client timeout.
     */
    public static final byte CONNECTION_TIMEOUT = -6;

    /**
     * Status code indicating that the response was lost, and the outcome of the invocation is unknown.
     */
    public static final byte RESPONSE_UNKNOWN = -7;

    /**
     * Status code indicating that the transaction is being restarted.  These are used internally to Volt
     * and shouldn't leak out to actual clients.
     */
    public static final byte TXN_RESTART = -8;

    /**
     * Default value for the user specified app status code field
     */
    public static final byte UNINITIALIZED_APP_STATUS_CODE = Byte.MIN_VALUE;

    /**
     * Retrieve the status code returned by the server
     * @return Status code
     */
    public byte getStatus();

    /**
     * Retrieve the status code returned by the stored procedure. This code is generated by the application and
     * not VoltDB. The default value is -128.
     * @return Status code
     */
    public byte getAppStatus();

    /**
     * Get the array of {@link org.voltdb.VoltTable} results returned by the stored procedure.
     * @return An array of results. Will never be <code>null</code>, but may be length 0.
     */
    public VoltTable[] getResults();

    /**
     * Get a <code>String</code> representation of any additional information the server may have included in
     * the response. This may be an stack trace, error message, etc.
     * @return A message or <code>null</code> if there is none.
     */
    public String getStatusString();

    /**
     * Get a <code>String</code> representation of any additional information the stored procedure may have included in
     * the response. This may be an stack trace, error message, etc. This is generated by the application
     * and not VoltDB. The default value is null.
     * @return A message or <code>null</code> if there is none.
     */
    public String getAppStatusString();

    /**
     * Get the <code>Exception</code> that caused the stored procedure to fail and roll back.
     * There is no guarantee that an <code>Exception</code> will be provided.
     * @return The <code>Exception</code> that caused the procedure to fail if it is available or <code>null</code>
     *         if none was provided in the response.
     */
    public Exception getException();

    /**
     * Get an estimate of the amount of time it took for the database
     * to process the transaction from the time it was received at the initiating node to the time
     * the initiating node got the response and queued it for transmission to the client.
     * This time is an ESTIMATE
     * @return Time in milliseconds the procedure spent in the cluster
     */
    public int getClusterRoundtrip();

    /**
     * Get the amount of time it took to run the transaction through the Client API, database, and back to the
     * callback.
     * @return Time in milliseconds the procedure took to roundtrip from the client to the server
     */
    public int getClientRoundtrip();
}
