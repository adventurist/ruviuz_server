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
        from app import Roof, RoofType, Section, Rtype
        total_area = 0
        i = 0

        print (args)
        for key in args[0]:
            print key
            print '\n'

            if isinstance(key, Section):

                # twidth = db.Column(db.DECIMAL(10, 3))
                # full = db.Column(db.Boolean)
                # empty = db.Column(db.DECIMAL(10, 3))
                # slope = db.Column(db.Float)
                # rid = db.Column(db.Integer, db.ForeignKey('roofs.id'))
                # sectiontype = db.relationship('SectionType', backref='section', cascade='all, delete-orphan',
                #                               uselist=False)
                # emptytype = db.relationship('EmptyType', backref='section', cascade='all, delete-orphan', uselist=False)

                m_section = key
                length = m_section.length
                width = m_section.width
                angle = m_section.slope
                full = m_section.full
                twidth = None
                # if not full:
                #     twidth = m_section.twidth
                #     empty_area = m_section.empty
                #     empty_type = m_section.emptytype

                if m_section.full > 0:
                    this_section = length * width
                    total_area += this_section

                else:
                    this_section = decimal.Decimal(length) * decimal.Decimal(decimal.Decimal(width) - m_section.empty)
                    total_area += this_section

                print "This section: " + str(this_section)
                print str(i) + ': ' + str(total_area)

                i += 1

        # print total_area
        return total_area

    def calculate_price(self, *args):
        from app import Roof, RoofType, Section, Rtype
        # section_type, mat_type, empt_type, area, empt_area, empt_num, floors, clean_factor, pitch = None
        # floors_factor = 0 if floors == 1 else 0.05
        # roof_price = mat_type * (area - empt_area) * empt_num * clean_factor * (1 + (floors * floors_factor)) * pitch
        roof = Roof.query.filter_by(id=self.rid).one_or_none()
        r_type = Rtype.query.filter_by(rid=self.rid).one_or_none()
        mat_type = RoofType.query.filter_by(id=r_type.tid).one_or_none()

        pitch = None
        enum = 0
        total_area = 0
        i = 0

        for key in args[0]:

            if isinstance(key, Section):

                m_section = key
                empty_area = 0
                length = m_section.length
                width = m_section.width
                angle = m_section.slope
                full = m_section.full
                twidth = m_section.twidth
                pitch = m_section.slope/1000 + 1
                print str(m_section.full)
                if m_section.full:
                    this_section = length * width
                    total_area += this_section

                else:
                    this_section = decimal.Decimal(length) * decimal.Decimal(decimal.Decimal(width) - m_section.empty)
                    total_area += this_section
                    enum += 1

                i += 1

                floors = roof.floors if roof.floors is not None else 1
                floors_factor = 0 if floors == 1 else 0.05
                clean_factor = 1.0625
                empty_factor = 0.0375 * (1 + enum)

                print 'Mat:type.price' + str(mat_type.price) + '\nEnum:' + str(enum) + '\nCleanfactor:' + str(clean_factor) + '\nPitch:' + str(pitch) + '\nTotalArea:' + str(total_area) + '\nfloors_factor:' + str(floors_factor)
                roof_price = mat_type.price * total_area * decimal.Decimal(empty_factor) * decimal.Decimal(clean_factor) * (1 + (floors + floors_factor)) * decimal.Decimal(pitch)
                print 'Mat:type' + str(mat_type) + '\nEnum:' + str(enum) + '\nCleanfactor:' + str(clean_factor) + '\nPitch:' + str(pitch) + '\nTotalArea:' + str(total_area) + '\nfloors_factor:' + str(floors_factor)
                print str(mat_type.price) + ' * ' + str(total_area.quantize(decimal.Decimal(".01"))) + ' * ' + str(empty_factor) + ' * ' + str(decimal.Decimal(clean_factor)) + ' * (' + str(1) + ' * (' + str(floors) + ' + ' + str(floors_factor) + ')) * ' + str(decimal.Decimal(pitch).quantize(decimal.Decimal(".01")))
                final_price = roof_price.quantize(decimal.Decimal(".01"), rounding=ROUND_HALF_UP)
                print final_price
                return final_price

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
