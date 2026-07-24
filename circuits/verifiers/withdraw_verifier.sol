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

contract Groth16Verifier {
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

    
    uint256 constant IC0x = 15197859084137699525991755066429595449611657982788946636286175753544640713963;
    uint256 constant IC0y = 465615698567786585460910256597112692345770658131529018580313872643662611502;
    
    uint256 constant IC1x = 516181039754861059600236030347706981179019387111707209798039421322715295671;
    uint256 constant IC1y = 10066845972195193931088823694191222153701371952272677982856600984674615358150;
    
    uint256 constant IC2x = 3499249264786171624442980354837780816822104120730634868577099831928251449830;
    uint256 constant IC2y = 6012269185549956560338423861689993356858861390092182726843617935184516267185;
    
    uint256 constant IC3x = 9590910698780319340484934092059144587112789916672587979205656520837566934389;
    uint256 constant IC3y = 12238951559111518367739766189631020580850473381244220265189338471445958939817;
    
    uint256 constant IC4x = 11996829991951685420688135861335429960367476151540032066653050017804935015995;
    uint256 constant IC4y = 8533542230807456447875178140374527834951693833324276169668552892486066478604;
    
    uint256 constant IC5x = 5746048794581212673715163207567897061487550887800581196489936654091203543276;
    uint256 constant IC5y = 10135007796587717714067427569753755005128348064494102223725681297930827381761;
    
    uint256 constant IC6x = 11109633665103148630120390276774752977778932462327765846160359771801663161943;
    uint256 constant IC6y = 20360935844338450712133210671269015937033713991477698640352808822340744997152;
    
    uint256 constant IC7x = 16708114285939131961007534463100375614166087083269706891522803391102306256744;
    uint256 constant IC7y = 15799893964409311247488722469572787210427865217036970420854448789072510014801;
    
    uint256 constant IC8x = 18452446749704879047234664060529236347296444614117061690133910273940209820712;
    uint256 constant IC8y = 9742884833842360861650212514779889101518161052634279127097850352270029446697;
    
    uint256 constant IC9x = 13398221644610829078234001207581747915574531178981737290235787012906232428889;
    uint256 constant IC9y = 13612289190884152911009511830873889147381633192043451137273968515594503503712;
    
    uint256 constant IC10x = 7434583535485053048758243875520381146567344718058878595317274538945451203504;
    uint256 constant IC10y = 14522974644016122947671596894582101032967938982825379719286978594976060586049;
    
    uint256 constant IC11x = 100135949802990800904010337434045167151540976887928405217716595718441693099;
    uint256 constant IC11y = 3311876983955227867792941547697120261286527107944878539553270400297122171414;
    
    uint256 constant IC12x = 11573204102802073096019114347849404560412732513619495193640300699437662089705;
    uint256 constant IC12y = 7681167805693914712137927030940374636881224160453719577385072681930910933376;
    
    uint256 constant IC13x = 5957677832416817510503058734057368692592412832570789704744723734637338047480;
    uint256 constant IC13y = 21180927908137421483320889594994571150826361283354128629487684760689173936351;
    
    uint256 constant IC14x = 20553562915161008161051740199417772334829468629718688888788384198438262505752;
    uint256 constant IC14y = 1545805346669494874873038757137628668056227651217628267306212052059443120773;
    
    uint256 constant IC15x = 3932888507087437437836832180580299019879307823862541942925409507704665071745;
    uint256 constant IC15y = 13719575201516703561229226498033408923172421076620757522542993595678003478247;
    
    uint256 constant IC16x = 19560560795328393238800676103808615467702936921467213718257416962604346000995;
    uint256 constant IC16y = 1792396173208513471614621382828410075139979769044454531922790666346708623280;
    
    uint256 constant IC17x = 20748333038102646591633260243095801701707510457450556469346641197611254401523;
    uint256 constant IC17y = 10387329139685136851286816407571829502183334705792222662907043809155926032662;
    
    uint256 constant IC18x = 12901484423100327923008218704746812683341099430211469813823287778605021885664;
    uint256 constant IC18y = 15486146329623941305873749845350691594568949193787202398236678759201670183099;
    
    uint256 constant IC19x = 7004199905255753510500049541141780541897691899147152179760156897773121724210;
    uint256 constant IC19y = 14681468508037826582976692229559451453916482569834629070279058247934797365004;
    
    uint256 constant IC20x = 618074559935606870301118977775819716251558393681604543553680965108904352583;
    uint256 constant IC20y = 19841995436782257682568139400158529151135650325151912249085055950397734871620;
    
    uint256 constant IC21x = 9165021768824632817460809049765526898420872355726426139861897082035347010015;
    uint256 constant IC21y = 8015728631503943875944459102169690432718351775276493901091850776295760178438;
    
    uint256 constant IC22x = 19230285197694203711798325753453915343087604423658655995163220283164362840956;
    uint256 constant IC22y = 19884481632838012076465404535585656377154398627824131163227234366403889116590;
    
    uint256 constant IC23x = 2399063532197782942580607911245471701411030188804258106197498889435107798887;
    uint256 constant IC23y = 2929578183536714929566994323422199881732932587642954052309892852159742676872;
    
    uint256 constant IC24x = 18087247874985115989921639512549549339535688694202404612337797935487364024624;
    uint256 constant IC24y = 6974725709683907822569200075023874228264510914020501910316263930706498389400;
    
    uint256 constant IC25x = 2269531511339360981673567093369106998288514544837802800956647645589527084734;
    uint256 constant IC25y = 14305563921265486718851687449253356936360878053080568441952455520237485671140;
    
 
    // Memory data
    uint16 constant pVk = 0;
    uint16 constant pPairing = 128;

    uint16 constant pLastMem = 896;

    function verifyProof(uint[2] calldata _pA, uint[2][2] calldata _pB, uint[2] calldata _pC, uint[25] calldata _pubSignals) public view returns (bool) {
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
            

            // Validate all evaluations
            let isValid := checkPairing(_pA, _pB, _pC, _pubSignals, pMem)

            mstore(0, isValid)
             return(0, 0x20)
         }
     }
 }
