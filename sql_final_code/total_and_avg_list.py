import sys
import libsnark.alt_bn128 as libsnark

"""
    readme:  see the last line of total_list.py  
"""

def sum_zk(values):
    l=len(values)
    total = sum(values)

    pb=libsnark.ProtoboardPub()
    pblist=[]
    mid_hierachy=[]
    hierachy_length=l
    while(hierachy_length>1):
        mid_hierachy.append(hierachy_length)
        hierachy_length=int(hierachy_length/2)+hierachy_length%2
    mid_hierachy.append(1)

    everyvalue=[]
    tmpvalue=[]
    # create variables
    for i in range(len(mid_hierachy)):
        newtmpvalue=[]
        for j in range(mid_hierachy[i]):

            if i == 0:
                everyvalue.append(values[j])
                newtmpvalue.append(values[j])

            else:
                if (j!=len(tmpvalue)-j-1 and len(tmpvalue)%2==1) or len(tmpvalue)%2==0:
                    everyvalue.append(tmpvalue[j]+tmpvalue[-j-1])
                    newtmpvalue.append(tmpvalue[j]+tmpvalue[-j-1])
                else:
                    everyvalue.append(tmpvalue[j])
                    newtmpvalue.append(tmpvalue[j])
            
        tmpvalue=newtmpvalue.copy()
    sum_index = len(everyvalue)-1

    '''
    get mean
    '''
    everyvalue.append(l)
    avg = total/l
    k = 0
    while(total >= 0):
        everyvalue.append(total)
        total -= l
        everyvalue.append(k)
        k += 1

    # create variables    
    for idx, val in enumerate(range(len(everyvalue)+1)):
        pblist.append(libsnark.PbVariable())
        pblist[idx].allocate(pb)
        pb.setpublic(pblist[idx])
    runnungsum=0

    # create constraints
    # sum
    for i in range(len(mid_hierachy)-1):
        newtmpvalue=[]
        for j in range(mid_hierachy[i+1]):
            if mid_hierachy[i]%2==1 and j==mid_hierachy[i+1]-1:
                pb.add_r1cs_constraint(libsnark.R1csConstraint(libsnark.LinearCombination(pblist[runnungsum+j]),
                                             libsnark.LinearCombination(1),
                                                    libsnark.LinearCombination(pblist[runnungsum+j+mid_hierachy[i]])))
                
            else:
                pb.add_r1cs_constraint(libsnark.R1csConstraint(libsnark.LinearCombination(pblist[runnungsum+j])+libsnark.LinearCombination(pblist[runnungsum+(mid_hierachy[i]-1-j)]),
                                             libsnark.LinearCombination(1),
                                                    libsnark.LinearCombination(pblist[runnungsum+j+mid_hierachy[i]])))
        runnungsum+=mid_hierachy[i]

    # avg
    for i in range(k-1):
        pb.add_r1cs_constraint(libsnark.R1csConstraint(libsnark.LinearCombination(pblist[sum_index+2+i*2])-libsnark.LinearCombination(pblist[sum_index+1]),
                                             libsnark.LinearCombination(1),
                                                    libsnark.LinearCombination(pblist[sum_index+4+i*2])))

        pb.add_r1cs_constraint(libsnark.R1csConstraint(libsnark.LinearCombination(pblist[sum_index+3+i*2])+libsnark.LinearCombination(1),
                                             libsnark.LinearCombination(1),
                                                    libsnark.LinearCombination(pblist[sum_index+5+i*2])))


    # create witnesses
    for pbs, val in zip(pblist, everyvalue):
        pb.setval(pbs, val)

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

    # print(f"*** Input {l} numbers: " + " ".join([str(pubvals.at(i)) for i in range(l)]))
    print(f"*** Sum: {str(pubvals.at(sum_index))}")
    print(f"*** Average: {str(pubvals.at(pubvals.size()-2))}")
    print("*** Verification status:", verified)



# sum_zk([1,2,3,4,5,4,3])
# sum_zk([i for i in range(0,100,2)])