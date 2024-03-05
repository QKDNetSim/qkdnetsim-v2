/*
 * Copyright (c) 2020 Lawrence Livermore National Laboratory
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation;
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * Author: Peter D. Barnes, Jr. <pdbarnes@llnl.gov>
 */

#include "example-as-test.h"

#include "ascii-test.h"
#include "assert.h"
#include "environment-variable.h"
#include "fatal-error.h"
#include "log.h"

#include <cstdlib> // itoa(), system ()
#include <cstring>
#include <sstream>
#include <string>

/**
 * \file
 * \ingroup testing
 * Implementation of classes ns3::ExampleAsTestSuite and ns3::ExampleTestCase.
 */

namespace ns3
{

NS_LOG_COMPONENT_DEFINE("ExampleAsTestCase");

// Running tests as examples currently requires Python.
#if defined(NS3_ENABLE_EXAMPLES)

ExampleAsTestCase::ExampleAsTestCase(const std::string name,
                                     const std::string program,
                                     const std::string dataDir,
                                     const std::string args /* = "" */,
                                     const bool shouldNotErr /* = true */)
    : TestCase(name),
      m_program(program),
      m_dataDir(dataDir),
      m_args(args),
      m_shouldNotErr(shouldNotErr)
{
    NS_LOG_FUNCTION(this << name << program << dataDir << args);
}

ExampleAsTestCase::~ExampleAsTestCase()
{
    NS_LOG_FUNCTION_NOARGS();
}

std::string
ExampleAsTestCase::GetCommandTemplate() const
{
    NS_LOG_FUNCTION_NOARGS();
    std::string command("%s ");
    command += m_args;
    return command;
}

std::string
ExampleAsTestCase::GetPostProcessingCommand() const
{
    NS_LOG_FUNCTION_NOARGS();
    std::string command("");
    return command;
}

void
ExampleAsTestCase::DoRun()
{
    NS_LOG_FUNCTION_NOARGS();
    // Set up the output file names
    SetDataDir(m_dataDir);
    std::string refFile = CreateDataDirFilename(GetName() + ".reflog");
    std::string testFile = CreateTempDirFilename(GetName() + ".reflog");
    std::string post = GetPostProcessingCommand();

    if (!m_shouldNotErr)
    {
        // Strip any system- or compiler-dependent messages
        // resulting from invoking NS_FATAL..., which in turn
        // calls std::terminate
        post += " | sed '1,/" + std::string(NS_FATAL_MSG) + "/!d' ";
    }

    std::stringstream ss;

    ss << "python3 ./ns3 run " << m_program << " --no-build --command-template=\""
       << GetCommandTemplate() << "\"";

    if (post.empty())
    {
        // redirect to testfile, then std::clog, std::cerr to std::cout
        ss << " > " << testFile << " 2>&1";
    }
    else
    {
        ss << " 2>&1 " << post << " > " << testFile;
    }

    int status = std::system(ss.str().c_str());

    std::cout << "\n"
              << GetName() << ":\n"
              << "    command:  " << ss.str() << "\n"
              << "    status:   " << status << "\n"
              << "    refFile:  " << refFile << "\n"
              << "    testFile: " << testFile << "\n"
              << "    testFile contents:" << std::endl;

    std::ifstream logF(testFile);
    std::string line;
    while (getline(logF, line))
    {
        std::cout << "--- " << line << "\n";
    }
    logF.close();

    if (m_shouldNotErr)
    {
        // Make sure the example didn't outright crash
        NS_TEST_ASSERT_MSG_EQ(status, 0, "example " + m_program + " failed");
    }

    // If we're just introspecting the command-line
    // we've run the example and we're done
    auto [found, intro] = EnvironmentVariable::Get("NS_COMMANDLINE_INTROSPECTION");
    if (found)
    {
        return;
    }

    // Compare the testFile to the reference file
    NS_ASCII_TEST_EXPECT_EQ(testFile, refFile);
}

ExampleAsTestSuite::ExampleAsTestSuite(const std::string name,
                                       const std::string program,
                                       const std::string dataDir,
                                       const std::string args /* = "" */,
                                       const TestDuration duration /* =QUICK */,
                                       const bool shouldNotErr /* = true */)
    : TestSuite(name, EXAMPLE)
{
    NS_LOG_FUNCTION(this << name << program << dataDir << args << duration << shouldNotErr);
    AddTestCase(new ExampleAsTestCase(name, program, dataDir, args, shouldNotErr), duration);
}

#endif // NS3_ENABLE_EXAMPLES

} // namespace ns3
