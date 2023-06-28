import sys
import libsnark.alt_bn128 as libsnark
import math

def pr_zk(pr,values):
    l=len(values)
    percentage=pr/100
    assert percentage<=1 and percentage>0, "pr should be 100>pr>0"
    values=sorted(values)
    # print(values)
    input_nb=math.ceil(percentage*l)
    
    pb=libsnark.ProtoboardPub()
    pblist=[]
    allvalue=[]
    hierachy_length=l
    one=libsnark.PbVariable()
    for i, val in enumerate(values):
        if i+1>input_nb: break
        allvalue.append(i+1)
        allvalue.append(val)
            
    for idx, val in enumerate(allvalue):
        pblist.append(libsnark.PbVariable())
        pblist[idx].allocate(pb)
        pb.setpublic(pblist[idx])

###constraint
    for  idx in  range(input_nb-1):
        pb.add_r1cs_constraint(libsnark.R1csConstraint(libsnark.LinearCombination(pblist[idx*2])+libsnark.LinearCombination(one),
                                             libsnark.LinearCombination(1),
                                                libsnark.LinearCombination(pblist[(idx+1)*2] )))
    # print(mid_hierachy)
    for pbs,val in zip(pblist,allvalue):
        pb.setval(pbs, val)
    
    pb.setval(one, 1)

    cs=pb.get_constraint_system_pubs()
    pubvals=pb.primary_input_pubs()
    privvals=pb.auxiliary_input_pubs()

    print("*** Trying to read key")
    keypair=libsnark.zk_read_key("ekfile", cs)
    if not keypair:
        print("*** No key or computation changed, generating keys...")
        keypair=libsnark.zk_generator(cs)
        libsnark.zk_write_keys(keypair, "vkfile", "ekfile")
        
    print("*** Generating proof (" +
        "sat=" + str(pb.is_satisfied()) + 
        ", #io=" + str(pubvals.size()) + 
        ", #witness=" + str(privvals.size()) + 
        ", #constraint=" + str(pb.num_constraints()) +
        ")")
        
    proof=libsnark.zk_prover(keypair.pk, pubvals, privvals)

    # print("proof is", pubvals)

    verified=libsnark.zk_verifier_strong_IC(keypair.vk, pubvals, proof)

    # print(f"*** Input {l} numbers: " + " ".join([str(pubvals.at(i)) for i in range(input_nb*2)]))
    print(f"*** pr: {str(pubvals.at(pubvals.size()-1))}")
    
    # print(f"*** Average: {str(pubvals.at(pubvals.size()-1))}")
    print("*** Verification status:", verified)


#readme: given the PR number, and input list to get the data which is the pr u want
# for example:  given pr_zk(50,list) will get median of list in a r1cs zero knowledge
# pr_zk(50,[1,3,5,7,9])