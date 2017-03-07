from rooftypes import Roof_types
import decimal
from decimal import ROUND_HALF_UP


class Calculator:
    rid = None
    roof_types = None

    def __init__(self, rid):
        self.rid = rid
        self.roof_types = Roof_types

    def calculate_price(self, *args):
        from app import Roof, RoofType, Section, Rtype, SectionTypes

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

                section_type = SectionTypes.query.filter_by(id=m_section.sectiontype.tid).one_or_none()

                length = m_section.length
                width = m_section.width
                twidth = m_section.twidth
                pitch = m_section.slope / 1000 + 1

                if section_type.name == "Mansard":
                    print 'We have mansard'
                    if twidth is not None and twidth == width:
                        print "(" + str(twidth) + " + " + str(width) + ")" + " * " + str(length) + " / " + str(2)
                        this_section = (twidth + width) * length / 2
                    elif twidth is not None and twidth != width:
                        this_section = (twidth + width) * length / 2
                    else:
                        this_section = (width * 2) * length / 2
                    total_area += this_section

                elif section_type.name == "Gable":
                    print "We have gable"
                    if twidth is not None and twidth == width:
                        this_section = 2 * width * length

                    elif twidth is not None and twidth != width:
                        print "Top width not equal to Bottom width"
                        this_section = 2 * ((twidth + width) / 2) * length
                    else:
                        print "Twidth not set"
                        this_section = 2 * ((width + width) / 2) * length
                    total_area += this_section

                elif section_type.name == "Hip:Square":
                    print "We have Hip:Square"
                    if twidth is None or twidth == 0:
                        this_section = length * width / 2
                    else:
                        print "Not a triangle"
                        this_section = (twidth + width) * length / 2
                    total_area += this_section

                elif section_type.name == "Hip:Rectangular":
                    print "We have Hip:Rectangular"
                    if twidth is not None and twidth > 0:
                        this_section = (twidth + width) * length / 2
                    else:
                        print "No top width"
                        this_section = length * width / 2
                    total_area += this_section

                elif section_type.name == "Lean-to-Roof":
                    print "We have Lean-to-Roof"
                    if twidth == width:
                        this_section = length * width
                    else:
                        print "Top width not equal to Bottom width"
                        this_section = (twidth + width) * length / 2
                    total_area += this_section

                if not m_section.full:
                    total_area -= m_section.empty
                    enum += 1

                i += 1

        floors = roof.floors if roof.floors is not None else 1
        print floors
        floors_factor = 0 if floors == 1 else 0.05
        clean_factor = 1.0625
        empty_factor = 0.0375 * (1 + enum)
        total_area = total_area.quantize(decimal.Decimal(".01"))

        print 'Mat:type.price' + str(mat_type.price) + '\nEnum:' + str(enum) + '\nCleanfactor:' + str(clean_factor) + \
              '\nPitch:' + str(pitch) + '\nTotalArea:' + str(total_area) + '\nfloors_factor:' + str(floors_factor)
        roof_price = mat_type.price * total_area * decimal.Decimal(empty_factor) * decimal.Decimal(clean_factor) * \
                     (1 + (floors + floors_factor)) * decimal.Decimal(pitch)
        print 'Mat:type' + str(mat_type) + '\nEnum:' + str(enum) + '\nCleanfactor:' + str(clean_factor) + '\nPitch:' \
              + str(pitch) + '\nTotalArea:' + str(total_area) + '\nfloors_factor:' + str(floors_factor)
        print str(mat_type.price) + ' * ' + str(total_area) + ' * ' + str(empty_factor) + ' * ' + \
              str(decimal.Decimal(clean_factor)) + ' * (' + str(1) + ' * (' + str(floors) + ' + ' + \
              str(floors_factor) + ')) * ' + str(decimal.Decimal(pitch).quantize(decimal.Decimal(".01")))
        final_price = roof_price.quantize(decimal.Decimal(".01"), rounding=ROUND_HALF_UP)
        print final_price
        return final_price, total_area

    def get_sections(self):
        from app import Section
        sections = Section.query.filter_by(rid=self.rid).all()
        if sections is None:
            return 'Error'
        else:
            return sections

    @staticmethod
    def get_estimate(area, type):
        for key, value in Roof_types.__dict__.items():
            if type == value:
                cost = area * decimal.Decimal(0.325 * value)
                return cost.quantize(decimal.Decimal(".01"), rounding=ROUND_HALF_UP)
