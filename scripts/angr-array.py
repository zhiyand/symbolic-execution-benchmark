import angr

p = angr.Project('../array.out');

ex = p.surveyors.Explorer()

ex.run()

# Needs manual interuption here

print ex
