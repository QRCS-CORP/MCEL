#include "functions_test.h"
#include "consoleutils.h"
#include "stringutils.h"

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

static void print_title(void)
{
	mclr_test_print_message("***************************************************");
	mclr_test_print_message("* MCEL: Merkle Chained Event Ledger Test          *");
	mclr_test_print_message("*                                                 *");
	mclr_test_print_message("* Release:   v1.0.0.0 (A1)                        *");
	mclr_test_print_message("* License:   QRCS-PL                              *");
	mclr_test_print_message("* Date:      January 30, 2026                     *");
	mclr_test_print_message("* Contact:   contact@qrcscorp.ca                  *");
	mclr_test_print_message("***************************************************");
	mclr_test_print_message("");
}

int main(void)
{
	print_title();

	mclr_test_print_message("Testing the MCEL internal functions.");
	mclr_test_print_message("");

	if (mceltest_functions_run() == true)
	{
		mclr_test_print_message("Success! The MCEL internal functions tests have passed.");
	}
	else
	{
		mclr_test_print_message("Failure! The MCEL internal functions tests have failed");
	}

	mclr_test_print_message("");
	mclr_test_print_message("Press any key to close...");
	qsc_consoleutils_get_wait();

	return 0;
}
