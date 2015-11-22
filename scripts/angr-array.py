import angr

p = angr.Project('../array.o');

ex = p.surveyors.Explorer()

ex.run()

# Needs manual interuption here

print ex
