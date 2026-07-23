/*! Copyright 2026 Fonticons, Inc. - https://webawesome.com/license */

// src/components/known-date/internal/partial-date-validator.ts
var PartialDateValidator = () => {
  return {
    checkValidity(element) {
      const host = element;
      const parts = host.parts;
      const empty = parts.day === "" && parts.month === "" && parts.year === "";
      const complete = parts.day !== "" && parts.month !== "" && parts.year !== "";
      if (empty) {
        return { isValid: true, invalidKeys: [], message: "" };
      }
      if (complete) {
        if (host.value === "") {
          const message2 = host.localize?.term("incompleteDate") || "Enter a valid date.";
          return { isValid: false, invalidKeys: ["badInput"], message: message2 };
        }
        return { isValid: true, invalidKeys: [], message: "" };
      }
      const message = host.localize?.term("incompleteDate") || "Enter a complete date.";
      return {
        isValid: false,
        invalidKeys: ["valueMissing"],
        message
      };
    }
  };
};

export {
  PartialDateValidator
};
