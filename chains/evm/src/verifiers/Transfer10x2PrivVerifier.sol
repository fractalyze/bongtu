// SPDX-License-Identifier: GPL-3.0
/*
    Copyright 2021 0KIMS association.

    This file is generated with [snarkJS](https://github.com/iden3/snarkjs).

    snarkJS is a free software: you can redistribute it and/or modify it
    under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    snarkJS is distributed in the hope that it will be useful, but WITHOUT
    ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
    or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public
    License for more details.

    You should have received a copy of the GNU General Public License
    along with snarkJS. If not, see <https://www.gnu.org/licenses/>.
*/

pragma solidity >=0.7.0 <0.9.0;

contract Transfer10x2PrivVerifier {
    // Scalar field size
    uint256 constant r    = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
    // Base field size
    uint256 constant q   = 21888242871839275222246405745257275088696311157297823662689037894645226208583;

    // Verification Key data
    uint256 constant alphax  = 20491192805390485299153009773594534940189261866228447918068658471970481763042;
    uint256 constant alphay  = 9383485363053290200918347156157836566562967994039712273449902621266178545958;
    uint256 constant betax1  = 4252822878758300859123897981450591353533073413197771768651442665752259397132;
    uint256 constant betax2  = 6375614351688725206403948262868962793625744043794305715222011528459656738731;
    uint256 constant betay1  = 21847035105528745403288232691147584728191162732299865338377159692350059136679;
    uint256 constant betay2  = 10505242626370262277552901082094356697409835680220590971873171140371331206856;
    uint256 constant gammax1 = 11559732032986387107991004021392285783925812861821192530917403151452391805634;
    uint256 constant gammax2 = 10857046999023057135944570762232829481370756359578518086990519993285655852781;
    uint256 constant gammay1 = 4082367875863433681332203403145435568316851327593401208105741076214120093531;
    uint256 constant gammay2 = 8495653923123431417604973247489272438418190587263600148770280649306958101930;
    uint256 constant deltax1 = 11559732032986387107991004021392285783925812861821192530917403151452391805634;
    uint256 constant deltax2 = 10857046999023057135944570762232829481370756359578518086990519993285655852781;
    uint256 constant deltay1 = 4082367875863433681332203403145435568316851327593401208105741076214120093531;
    uint256 constant deltay2 = 8495653923123431417604973247489272438418190587263600148770280649306958101930;

    
    uint256 constant IC0x = 3461486408326208432709776926559626359844334850975623623038109168968390735542;
    uint256 constant IC0y = 17184665852742112725532687560324054647177532072139668079498337495246231336075;
    
    uint256 constant IC1x = 8461755008961575804261200494668252870197710416726533714963842853816393743857;
    uint256 constant IC1y = 938107353464593719186733777943535514184481193754671168695550564928606063566;
    
    uint256 constant IC2x = 4090383126995574509657585381719410086970297510218703147438302381689533805076;
    uint256 constant IC2y = 17517593718289951618417350312554929300857049539207134966165106361947227268134;
    
    uint256 constant IC3x = 1157870803281030322701998546433731826036505800680435518237364592529960767033;
    uint256 constant IC3y = 3703809394312797353510781484408166289156117799598292918393082826443633500706;
    
    uint256 constant IC4x = 15016740532532802424876161196637340902034193353585586916655348251496213057092;
    uint256 constant IC4y = 5886107797950099119894194385632189336256301271648025561896350589955917856088;
    
    uint256 constant IC5x = 16542988859370612887168978107243799593321409047735910787297868458216881233817;
    uint256 constant IC5y = 3963676143417924529620376057109748468939091356044845760116929366083879408559;
    
    uint256 constant IC6x = 15077144849991120427156189825362370821047817379313382228427216470221423336241;
    uint256 constant IC6y = 6235086603918649588887808018219403191495838946002006864104444064947647250634;
    
    uint256 constant IC7x = 17351120793634117580906103650630622288372831771401440993989631177796093067592;
    uint256 constant IC7y = 92310888639996299323184507111628543930979160063671655715528740304927703915;
    
    uint256 constant IC8x = 11786715578976261220906168620099271273887633558708876971785007990894041960347;
    uint256 constant IC8y = 19826247905422589137206740564791302075769078096288598253079965157503680722951;
    
    uint256 constant IC9x = 20623652275494010830337748366288702114562687866778812071975910094454755820395;
    uint256 constant IC9y = 11838391777300839359684480159687199542265755887890505207434618829887911960929;
    
    uint256 constant IC10x = 19850572985843976723803108456755277608640860889908428181384354393190140748794;
    uint256 constant IC10y = 20561179629921737192733050232672043833214735256801241249082920877349404442194;
    
    uint256 constant IC11x = 16027189065667743853611245061032452466323697755604124496342463447348120536245;
    uint256 constant IC11y = 10565355549120413711924968918507645984511538007866851409070853075681253492983;
    
    uint256 constant IC12x = 10684209190264157910080627284151837608096970169848134967866436734206896483812;
    uint256 constant IC12y = 6100044731883005883243631970804660291126286792807929431163551900375502187893;
    
    uint256 constant IC13x = 17488042149312513402119549504707553487707438486716816176048389936162595153047;
    uint256 constant IC13y = 19936689089067993984737816833983406356621531109189714916822658629159331702491;
    
    uint256 constant IC14x = 1245043307977434109805995773834881253942259975763217327987311329867589261254;
    uint256 constant IC14y = 20029592868494219826651437810460734791431094204823814123869418727779454455517;
    
    uint256 constant IC15x = 14061915543647535993140894486898935263646204524261388174935060150133758651219;
    uint256 constant IC15y = 15100391749218137888920418044634218927492967240818171841014256363048070981817;
    
    uint256 constant IC16x = 391818341286824387237917735981542742053919805135007800918056394570832907423;
    uint256 constant IC16y = 11868006730376934246850442732411138175937166023680395803565854103975553130574;
    
    uint256 constant IC17x = 16734455829740365616262954531398891256292177518863954087325001163095884806673;
    uint256 constant IC17y = 9348897748586367579197633689376392728214750523224127039848846488755124052086;
    
    uint256 constant IC18x = 9919619910930687879215812526173785581009482960906258525679316251668147417219;
    uint256 constant IC18y = 8124994674968216771864514173367329472252099303004656532922416322696512283009;
    
    uint256 constant IC19x = 1109416151626023033136831252648544005327103759479559403210192998281971072478;
    uint256 constant IC19y = 17351245114180536080274500881345196516785867893787412281206678043773176971732;
    
    uint256 constant IC20x = 20141389250783474211345044692018911445574679521286258795113372925381907242221;
    uint256 constant IC20y = 5725188454277509545476361140093766209638820524045132833553906413478226148803;
    
    uint256 constant IC21x = 21466789389248469278198062015779808338320424042486088370438345563148321485591;
    uint256 constant IC21y = 14476204193041600165465274244207210959925698668814715305475484554590570180755;
    
    uint256 constant IC22x = 15739597682467650524993029963773599022891975437557070770789298849156807661502;
    uint256 constant IC22y = 17315366341155825044961917168629137696476176861027778025953267107496930850215;
    
    uint256 constant IC23x = 14054545476242034869654143640771373825183741519730986255506624168305094671828;
    uint256 constant IC23y = 12606851840867517128723234226532067870701304443621503102031541956502745230360;
    
    uint256 constant IC24x = 18108524621523244108103352752575996264796812101450911139303909238741847780291;
    uint256 constant IC24y = 11730319256937840553200018077991239308487059535689673712248404321449138506019;
    
    uint256 constant IC25x = 5827092744865918049080993056058224210706367685525305594389244925091118265057;
    uint256 constant IC25y = 18191344613380533605453100002742719229740495734596126885355866847799461172759;
    
    uint256 constant IC26x = 7489358809093561092811617050641493591045621111693374599862233875759019777175;
    uint256 constant IC26y = 18432401185828296945618388620920955627762847534202556099021208585046169849384;
    
    uint256 constant IC27x = 2503604302021310902859366978811774510789317953065610706298372338582666066658;
    uint256 constant IC27y = 20527934183274872321033372631621569567198586050379091143999569752610114216902;
    
    uint256 constant IC28x = 9138671594597741480741954477151487808668057597838232977916596943232381696820;
    uint256 constant IC28y = 15617287089456269953379544010253323886366663595463915336276015544116813037153;
    
    uint256 constant IC29x = 8492240043557056961772253281329120086665344756894068003791564014990949629692;
    uint256 constant IC29y = 6316716601697882723282828958797397272035547479703243274258291068124181487672;
    
    uint256 constant IC30x = 15816264536697157320206399435902072819418477190910031415323443000651711844620;
    uint256 constant IC30y = 10024255998445507741248002939606660938878040790590050416306246203189389017570;
    
    uint256 constant IC31x = 203125164973290871613167431966108886766008867053141779479262831179895541422;
    uint256 constant IC31y = 13768823891794532894889360972734770184804730165123333807813264714248761352610;
    
    uint256 constant IC32x = 19790916772689793502478605727367197720922198738711678705510953843985313255692;
    uint256 constant IC32y = 2939676629069718769283265162974311399771597317824293974378753613886219520598;
    
    uint256 constant IC33x = 12376624808417528673041535104808513771318823448152772663403648234042235912201;
    uint256 constant IC33y = 7588216770298812074998568752369083585464722814972677633381646183552015115083;
    
    uint256 constant IC34x = 1233361480160198191759914909219559415398071937429879420928817670912551999755;
    uint256 constant IC34y = 19611406335647539000624222782735384084989523366861086224392073168005417126464;
    
    uint256 constant IC35x = 21842715111685023529622035119850230740771719538971250145645038858666081574173;
    uint256 constant IC35y = 2906425751463721780803022657011496706095348571614776104362022809449113677316;
    
    uint256 constant IC36x = 17769397415364155453410073484023361717708269585919098999666972600153197409954;
    uint256 constant IC36y = 1694071437531184205768179976824599445776705697814669811130835185503086453520;
    
 
    // Memory data
    uint16 constant pVk = 0;
    uint16 constant pPairing = 128;

    uint16 constant pLastMem = 896;

    function verifyProof(uint[2] calldata _pA, uint[2][2] calldata _pB, uint[2] calldata _pC, uint[36] calldata _pubSignals) public view returns (bool) {
        assembly {
            function checkField(v) {
                if iszero(lt(v, r)) {
                    mstore(0, 0)
                    return(0, 0x20)
                }
            }
            
            // G1 function to multiply a G1 value(x,y) to value in an address
            function g1_mulAccC(pR, x, y, s) {
                let success
                let mIn := mload(0x40)
                mstore(mIn, x)
                mstore(add(mIn, 32), y)
                mstore(add(mIn, 64), s)

                success := staticcall(sub(gas(), 2000), 7, mIn, 96, mIn, 64)

                if iszero(success) {
                    mstore(0, 0)
                    return(0, 0x20)
                }

                mstore(add(mIn, 64), mload(pR))
                mstore(add(mIn, 96), mload(add(pR, 32)))

                success := staticcall(sub(gas(), 2000), 6, mIn, 128, pR, 64)

                if iszero(success) {
                    mstore(0, 0)
                    return(0, 0x20)
                }
            }

            function checkPairing(pA, pB, pC, pubSignals, pMem) -> isOk {
                let _pPairing := add(pMem, pPairing)
                let _pVk := add(pMem, pVk)

                mstore(_pVk, IC0x)
                mstore(add(_pVk, 32), IC0y)

                // Compute the linear combination vk_x
                
                g1_mulAccC(_pVk, IC1x, IC1y, calldataload(add(pubSignals, 0)))
                
                g1_mulAccC(_pVk, IC2x, IC2y, calldataload(add(pubSignals, 32)))
                
                g1_mulAccC(_pVk, IC3x, IC3y, calldataload(add(pubSignals, 64)))
                
                g1_mulAccC(_pVk, IC4x, IC4y, calldataload(add(pubSignals, 96)))
                
                g1_mulAccC(_pVk, IC5x, IC5y, calldataload(add(pubSignals, 128)))
                
                g1_mulAccC(_pVk, IC6x, IC6y, calldataload(add(pubSignals, 160)))
                
                g1_mulAccC(_pVk, IC7x, IC7y, calldataload(add(pubSignals, 192)))
                
                g1_mulAccC(_pVk, IC8x, IC8y, calldataload(add(pubSignals, 224)))
                
                g1_mulAccC(_pVk, IC9x, IC9y, calldataload(add(pubSignals, 256)))
                
                g1_mulAccC(_pVk, IC10x, IC10y, calldataload(add(pubSignals, 288)))
                
                g1_mulAccC(_pVk, IC11x, IC11y, calldataload(add(pubSignals, 320)))
                
                g1_mulAccC(_pVk, IC12x, IC12y, calldataload(add(pubSignals, 352)))
                
                g1_mulAccC(_pVk, IC13x, IC13y, calldataload(add(pubSignals, 384)))
                
                g1_mulAccC(_pVk, IC14x, IC14y, calldataload(add(pubSignals, 416)))
                
                g1_mulAccC(_pVk, IC15x, IC15y, calldataload(add(pubSignals, 448)))
                
                g1_mulAccC(_pVk, IC16x, IC16y, calldataload(add(pubSignals, 480)))
                
                g1_mulAccC(_pVk, IC17x, IC17y, calldataload(add(pubSignals, 512)))
                
                g1_mulAccC(_pVk, IC18x, IC18y, calldataload(add(pubSignals, 544)))
                
                g1_mulAccC(_pVk, IC19x, IC19y, calldataload(add(pubSignals, 576)))
                
                g1_mulAccC(_pVk, IC20x, IC20y, calldataload(add(pubSignals, 608)))
                
                g1_mulAccC(_pVk, IC21x, IC21y, calldataload(add(pubSignals, 640)))
                
                g1_mulAccC(_pVk, IC22x, IC22y, calldataload(add(pubSignals, 672)))
                
                g1_mulAccC(_pVk, IC23x, IC23y, calldataload(add(pubSignals, 704)))
                
                g1_mulAccC(_pVk, IC24x, IC24y, calldataload(add(pubSignals, 736)))
                
                g1_mulAccC(_pVk, IC25x, IC25y, calldataload(add(pubSignals, 768)))
                
                g1_mulAccC(_pVk, IC26x, IC26y, calldataload(add(pubSignals, 800)))
                
                g1_mulAccC(_pVk, IC27x, IC27y, calldataload(add(pubSignals, 832)))
                
                g1_mulAccC(_pVk, IC28x, IC28y, calldataload(add(pubSignals, 864)))
                
                g1_mulAccC(_pVk, IC29x, IC29y, calldataload(add(pubSignals, 896)))
                
                g1_mulAccC(_pVk, IC30x, IC30y, calldataload(add(pubSignals, 928)))
                
                g1_mulAccC(_pVk, IC31x, IC31y, calldataload(add(pubSignals, 960)))
                
                g1_mulAccC(_pVk, IC32x, IC32y, calldataload(add(pubSignals, 992)))
                
                g1_mulAccC(_pVk, IC33x, IC33y, calldataload(add(pubSignals, 1024)))
                
                g1_mulAccC(_pVk, IC34x, IC34y, calldataload(add(pubSignals, 1056)))
                
                g1_mulAccC(_pVk, IC35x, IC35y, calldataload(add(pubSignals, 1088)))
                
                g1_mulAccC(_pVk, IC36x, IC36y, calldataload(add(pubSignals, 1120)))
                

                // -A
                mstore(_pPairing, calldataload(pA))
                mstore(add(_pPairing, 32), mod(sub(q, calldataload(add(pA, 32))), q))

                // B
                mstore(add(_pPairing, 64), calldataload(pB))
                mstore(add(_pPairing, 96), calldataload(add(pB, 32)))
                mstore(add(_pPairing, 128), calldataload(add(pB, 64)))
                mstore(add(_pPairing, 160), calldataload(add(pB, 96)))

                // alpha1
                mstore(add(_pPairing, 192), alphax)
                mstore(add(_pPairing, 224), alphay)

                // beta2
                mstore(add(_pPairing, 256), betax1)
                mstore(add(_pPairing, 288), betax2)
                mstore(add(_pPairing, 320), betay1)
                mstore(add(_pPairing, 352), betay2)

                // vk_x
                mstore(add(_pPairing, 384), mload(add(pMem, pVk)))
                mstore(add(_pPairing, 416), mload(add(pMem, add(pVk, 32))))


                // gamma2
                mstore(add(_pPairing, 448), gammax1)
                mstore(add(_pPairing, 480), gammax2)
                mstore(add(_pPairing, 512), gammay1)
                mstore(add(_pPairing, 544), gammay2)

                // C
                mstore(add(_pPairing, 576), calldataload(pC))
                mstore(add(_pPairing, 608), calldataload(add(pC, 32)))

                // delta2
                mstore(add(_pPairing, 640), deltax1)
                mstore(add(_pPairing, 672), deltax2)
                mstore(add(_pPairing, 704), deltay1)
                mstore(add(_pPairing, 736), deltay2)


                let success := staticcall(sub(gas(), 2000), 8, _pPairing, 768, _pPairing, 0x20)

                isOk := and(success, mload(_pPairing))
            }

            let pMem := mload(0x40)
            mstore(0x40, add(pMem, pLastMem))

            // Validate that all evaluations ∈ F
            
            checkField(calldataload(add(_pubSignals, 0)))
            
            checkField(calldataload(add(_pubSignals, 32)))
            
            checkField(calldataload(add(_pubSignals, 64)))
            
            checkField(calldataload(add(_pubSignals, 96)))
            
            checkField(calldataload(add(_pubSignals, 128)))
            
            checkField(calldataload(add(_pubSignals, 160)))
            
            checkField(calldataload(add(_pubSignals, 192)))
            
            checkField(calldataload(add(_pubSignals, 224)))
            
            checkField(calldataload(add(_pubSignals, 256)))
            
            checkField(calldataload(add(_pubSignals, 288)))
            
            checkField(calldataload(add(_pubSignals, 320)))
            
            checkField(calldataload(add(_pubSignals, 352)))
            
            checkField(calldataload(add(_pubSignals, 384)))
            
            checkField(calldataload(add(_pubSignals, 416)))
            
            checkField(calldataload(add(_pubSignals, 448)))
            
            checkField(calldataload(add(_pubSignals, 480)))
            
            checkField(calldataload(add(_pubSignals, 512)))
            
            checkField(calldataload(add(_pubSignals, 544)))
            
            checkField(calldataload(add(_pubSignals, 576)))
            
            checkField(calldataload(add(_pubSignals, 608)))
            
            checkField(calldataload(add(_pubSignals, 640)))
            
            checkField(calldataload(add(_pubSignals, 672)))
            
            checkField(calldataload(add(_pubSignals, 704)))
            
            checkField(calldataload(add(_pubSignals, 736)))
            
            checkField(calldataload(add(_pubSignals, 768)))
            
            checkField(calldataload(add(_pubSignals, 800)))
            
            checkField(calldataload(add(_pubSignals, 832)))
            
            checkField(calldataload(add(_pubSignals, 864)))
            
            checkField(calldataload(add(_pubSignals, 896)))
            
            checkField(calldataload(add(_pubSignals, 928)))
            
            checkField(calldataload(add(_pubSignals, 960)))
            
            checkField(calldataload(add(_pubSignals, 992)))
            
            checkField(calldataload(add(_pubSignals, 1024)))
            
            checkField(calldataload(add(_pubSignals, 1056)))
            
            checkField(calldataload(add(_pubSignals, 1088)))
            
            checkField(calldataload(add(_pubSignals, 1120)))
            

            // Validate all evaluations
            let isValid := checkPairing(_pA, _pB, _pC, _pubSignals, pMem)

            mstore(0, isValid)
             return(0, 0x20)
         }
     }
 }
