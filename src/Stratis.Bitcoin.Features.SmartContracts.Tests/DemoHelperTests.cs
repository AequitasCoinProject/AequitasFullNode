﻿using Stratis.SmartContracts.Core;
using Stratis.SmartContracts.ReflectionExecutor.Compilation;
using Xunit;

public class DemoHelperTests
{
    [Fact]
    public void GetHexStringForDemo()
    {
        SmartContractCompilationResult compilationResult = SmartContractCompiler.CompileFile("SmartContracts/Auction.cs");
        string example = compilationResult.Compilation.ToHexString();
    }
}