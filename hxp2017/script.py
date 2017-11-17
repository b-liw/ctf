import sys
import r2pipe
import string

r2 = r2pipe.open("./zwiebel")

def step_in():
  r2.cmd("ds")
  r2.cmd("sr rip")
  #print r2.cmd("pd 1")

def get_instructions(n):
  return r2.cmdj("pdj %d" % n)

def get_flag_offset(inst):
  offset = inst.split("rax")[1][:-1]
  if offset == "":
    offset = "0"
  return int(offset, 16)

def get_and_operand(inst):
  return int(inst.split(", ")[1], 16)

def set_breakpoint(addr):
  r2.cmd("db " + addr)

def set_register(reg, value):
  r2.cmd("dr %s=%d" % (reg, value))

def main():
  addr = "0x4006a3"
  r2.cmd("e dbg.profile=rarun2")
  r2.cmd("doo")
  set_breakpoint(addr)
  r2.cmd("dc")

  flag = [0x20] * 50

  while True:
    try:
      instructions = []
      while True:
        step_in()
        current = get_instructions(1)[0]
        instructions.append(current['opcode'])
        if "jecxz" in current['opcode']:
            break

      # possible cases in dissasembly
      if "nop" in instructions[-3] and "nop" in instructions[-4]:
        offset = get_flag_offset(instructions[-5])
        and_value = get_and_operand(instructions[-2])
        flag[offset] = flag[offset] | and_value
      elif "and" in instructions[-2] and "not" in instructions[-3]:
        offset = get_flag_offset(instructions[-4])
        and_value = get_and_operand(instructions[-2])
        flag[offset] = flag[offset] & (0xFF ^ and_value)
      elif "and" in instructions[-2] and "nop" in instructions[-3]:
        offset = get_flag_offset(instructions[-4])
        and_value = int(instructions[-2].split(", ")[1], 16)
        flag[offset] = flag[offset] | and_value
      elif "jecxz" in instructions[-1] and "cmp" in instructions[-2] and "inc" in instructions[-3]:
        set_register("ecx", 1)
        continue
      else:
        print "OPERATION NOT DEFINED"
        sys.exit()

      set_register("ecx", 1)

      while True:
        step_in()
        if "loop" in get_instructions(1)[0]['opcode']:
          break

      decoded_code = hex(get_instructions(2)[1]['jump'])
      set_breakpoint(decoded_code)
      r2.cmd("dc")
    except KeyError:
      print "".join([chr(x) for x in flag]).strip()
      break


if __name__ == "__main__":
    main()
