from rooftypes import Roof_types
import decimal
from decimal import ROUND_HALF_UP


class Calculator:
    rid = None
    roof_types = None

    def __init__(self, rid):
        self.rid = rid
        self.roof_types = Roof_types

    @staticmethod
    def calculate(*args):
        from app import Section
        total_area = 0
        i = 0
        print (args)
        for key in args[0]:
            print key
            print '\n'

            if isinstance(key, Section):

                m_section = key
                length = m_section.length
                width = m_section.width
                angle = m_section.slope

                if m_section.full > 0:
                    this_section = length * angle
                    total_area += this_section

                else:
                    this_section = decimal.Decimal(length) * decimal.Decimal(decimal.Decimal(angle) - m_section.empty)
                    total_area += this_section

                print "This section: " + str(this_section)
                print str(i) + ': ' + str(total_area)

                i += 1

        # print total_area
        return total_area

    def get_sections(self):
        from app import Section
        sections = Section.query.filter_by(rid=self.rid).all()
        # print (sections)
        if sections is None:
            return 'Error'
        else:
            return sections

    @staticmethod
    def get_estimate(area, type):
        # print area
        # print type
        for key, value in Roof_types.__dict__.items():
            # print value
            if type == value:
                # print 'Found match!'
                cost = area * decimal.Decimal(0.325 * value)
                # print (area)
                # print (value)
                # print (cost)
                return cost.quantize(decimal.Decimal(".01"), rounding=ROUND_HALF_UP)

# if __name__ == '__main__':
#     from app import Section
#     Calculator.debug = True
#
#     roof_id = 44
#
#     section1 = Section(length=20, width=10, full=1, slope=35)
#     section2 = Section(length=15, width=8, full=0, empty=60, slope=35)
#     section4 = Section(length=12, width=77, full=0, empty=9, slope=25)
#     section5 = Section(length=2, width=10, full=1, slope=35)
#     section6 = Section(length=15, width=8, full=0, empty=60, slope=35)
#
#     section_list = [section1, section2, section4, section5, section6]
#     area = Calculator(roof_id).calculate(section_list)
#     print (area)
#     rtype = Roof_types.PVC_50
#
#     estimate = Calculator(roof_id).get_estimate(area, rtype)
#
#     print estimate
