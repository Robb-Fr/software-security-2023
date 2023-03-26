/* ###
 * IP: Apache License 2.0 with LLVM Exceptions
 */
/* ----------------------------------------------------------------------------
 * This file was automatically generated by SWIG (http://www.swig.org).
 * Version 4.0.1
 *
 * Do not make changes to this file unless you know what you are doing--modify
 * the SWIG interface file instead.
 * ----------------------------------------------------------------------------- */

package SWIG;

public final class FunctionNameType {
  public final static FunctionNameType eFunctionNameTypeNone = new FunctionNameType("eFunctionNameTypeNone", lldbJNI.eFunctionNameTypeNone_get());
  public final static FunctionNameType eFunctionNameTypeAuto = new FunctionNameType("eFunctionNameTypeAuto", lldbJNI.eFunctionNameTypeAuto_get());
  public final static FunctionNameType eFunctionNameTypeFull = new FunctionNameType("eFunctionNameTypeFull", lldbJNI.eFunctionNameTypeFull_get());
  public final static FunctionNameType eFunctionNameTypeBase = new FunctionNameType("eFunctionNameTypeBase", lldbJNI.eFunctionNameTypeBase_get());
  public final static FunctionNameType eFunctionNameTypeMethod = new FunctionNameType("eFunctionNameTypeMethod", lldbJNI.eFunctionNameTypeMethod_get());
  public final static FunctionNameType eFunctionNameTypeSelector = new FunctionNameType("eFunctionNameTypeSelector", lldbJNI.eFunctionNameTypeSelector_get());
  public final static FunctionNameType eFunctionNameTypeAny = new FunctionNameType("eFunctionNameTypeAny", lldbJNI.eFunctionNameTypeAny_get());

  public final int swigValue() {
    return swigValue;
  }

  public String toString() {
    return swigName;
  }

  public static FunctionNameType swigToEnum(int swigValue) {
    if (swigValue < swigValues.length && swigValue >= 0 && swigValues[swigValue].swigValue == swigValue)
      return swigValues[swigValue];
    for (int i = 0; i < swigValues.length; i++)
      if (swigValues[i].swigValue == swigValue)
        return swigValues[i];
    throw new IllegalArgumentException("No enum " + FunctionNameType.class + " with value " + swigValue);
  }

  private FunctionNameType(String swigName) {
    this.swigName = swigName;
    this.swigValue = swigNext++;
  }

  private FunctionNameType(String swigName, int swigValue) {
    this.swigName = swigName;
    this.swigValue = swigValue;
    swigNext = swigValue+1;
  }

  private FunctionNameType(String swigName, FunctionNameType swigEnum) {
    this.swigName = swigName;
    this.swigValue = swigEnum.swigValue;
    swigNext = this.swigValue+1;
  }

  private static FunctionNameType[] swigValues = { eFunctionNameTypeNone, eFunctionNameTypeAuto, eFunctionNameTypeFull, eFunctionNameTypeBase, eFunctionNameTypeMethod, eFunctionNameTypeSelector, eFunctionNameTypeAny };
  private static int swigNext = 0;
  private final int swigValue;
  private final String swigName;
}

