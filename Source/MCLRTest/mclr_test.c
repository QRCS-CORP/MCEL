/* 2025 Quantum Resistant Cryptographic Solutions Corporation
 * All Rights Reserved.
 *
 * NOTICE: This software and all accompanying materials are the exclusive
 * property of Quantum Resistant Cryptographic Solutions Corporation (QRCS).
 * The intellectual and technical concepts contained within this implementation
 * are proprietary to QRCS and its authorized licensors and are protected under
 * applicable U.S. and international copyright, patent, and trade secret laws.
 *
 * CRYPTOGRAPHIC STANDARDS:
 * - This software includes implementations of cryptographic algorithms such as
 *   SHA3, AES, and others. These algorithms are public domain or standardized
 *   by organizations such as NIST and are NOT the property of QRCS.
 * - However, all source code, optimizations, and implementations in this library
 *   are original works of QRCS and are protected under this license.
 *
 * RESTRICTIONS:
 * - Redistribution, modification, or unauthorized distribution of this software,
 *   in whole or in part, is strictly prohibited.
 * - This software is provided for non-commercial, educational, and research
 *   purposes only. Commercial use in any form is expressly forbidden.
 * - Licensing and authorized distribution are solely at the discretion of QRCS.
 * - Any use of this software implies acceptance of these restrictions.
 *
 * DISCLAIMER:
 * This software is provided "as is," without warranty of any kind, express or
 * implied, including but not limited to warranties of merchantability or fitness
 * for a particular purpose. QRCS disclaims all liability for any direct, indirect,
 * incidental, or consequential damages resulting from the use or misuse of this software.
 *
 * FULL LICENSE:
 * This software is subject to the **Quantum Resistant Cryptographic Solutions
 * Proprietary License (QRCS-PL)**. The complete license terms are included
 * in the LICENSE.txt file distributed with this software.
 *
 * Written by: John G. Underhill
 * Contact: contact@qrcscorp.ca
 */

#include "mclr_example.h"
#include "consoleutils.h"
#include "stringutils.h"

static void mclr_test_print_error(char* desc, mclr_errors error)
{
    const char* msg;

    qsc_consoleutils_print_safe(desc);
    msg = mclr_error_to_string(error);

    if (msg != NULL)
    {
        qsc_consoleutils_print_line(msg);
    }
}

static void mclr_test_print_message(const char* message)
{
    size_t slen;

    if (message != NULL)
    {
        slen = qsc_stringutils_string_size(message);

        if (slen != 0U)
        {
            qsc_consoleutils_print_line(message);
        }
        else
        {
            qsc_consoleutils_print_line("");
        }
    }
}

static void mclr_test_print_title(void)
{
    mclr_test_print_message("***************************************************");
    mclr_test_print_message("* MCLR: Merkle Chained Log Record (MCLR) Test     *");
    mclr_test_print_message("*                                                 *");
    mclr_test_print_message("* Release:   v1.0.0.0 (A1)                        *");
    mclr_test_print_message("* License:   QRCS-PL                              *");
    mclr_test_print_message("* Date:      January 30, 2026                     *");
    mclr_test_print_message("* Contact:   contact@qrcscorp.ca                  *");
    mclr_test_print_message("***************************************************");
    mclr_test_print_message("");
}

static bool mclr_tests_run()
{
    uint8_t blkroot[MCEL_BLOCK_HASH_SIZE] = { 0U };
    uint8_t bundle[MCEL_CHECKPOINT_BUNDLE_ENCODED_SIZE] = { 0U };
    uint8_t reccommits[3U * MCEL_BLOCK_HASH_SIZE] = { 0U };
    mclr_errors err;

    err = mclr_example_initialization_test(); 

    if (err == mclr_error_none)
    {
        mclr_test_print_message("Success! Initialization test has passed.");

        err = mclr_example_append_record_test();

        if (err == mclr_error_none)
        {
            mclr_test_print_message("Success! Record append test has passed.");

            err = mclr_example_block_seal_test(blkroot, reccommits);

            if (err == mclr_error_none)
            {
                mclr_test_print_message("Success! Block seal test has passed.");

                err = mclr_example_checkpoint_seal_test(blkroot, bundle);

                if (err == mclr_error_none)
                {
                    mclr_test_print_message("Success! Checkpoint seal test has passed.");

                    err = mclr_example_export_checkpoint_test(blkroot, bundle);

                    if (err == mclr_error_none)
                    {
                        mclr_test_print_message("Success! Export budle test has passed.");

                        err = mclr_example_inclusion_proof_test(blkroot, bundle, reccommits);

                        if (err == mclr_error_none)
                        {
                            mclr_test_print_message("Success! Inclusion proof test has passed.");
                        }
                        else
                        {
                            mclr_test_print_error(" Prove inclusion failed: ", err);
                        }
                    }
                    else
                    {
                        mclr_test_print_error("Export bundle failed: ", err);
                    }
                }
                else
                {
                    mclr_test_print_error("Seal checkpoint failed: ", err);
                }
            }
            else
            {
                mclr_test_print_error("Seal block failed: ", err);
            }
        }
        else
        {
            mclr_test_print_error("Append failed: ", err);
        }
    }
    else
    {
        mclr_test_print_error("mclr ledger_initialize failed: ", err);
    }

    mclr_example_cleanup();

    return (err == mclr_error_none);
}

int main(void)
{
    mclr_test_print_title();

    mclr_test_print_message("Running the MCLR example function set.");
    mclr_test_print_message("");

    if (mclr_tests_run() == true)
    {
        mclr_test_print_message("Success! The MCLR function tests have succeeded.");
    }
    else
    {
        mclr_test_print_message("Failure! The MCLR function tests have failed.");
    }

    mclr_test_print_message("");
    mclr_test_print_message("Press any key to close...");
    qsc_consoleutils_get_wait();

    return 0;
}
