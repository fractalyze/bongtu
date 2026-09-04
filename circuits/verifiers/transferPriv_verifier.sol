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

    
    uint256 constant IC0x = 1044667344997441256202579953573510677205643823640364331235512014157550460575;
    uint256 constant IC0y = 16191773714223604955474220231299134764483401414130186684571645496013401922063;
    
    uint256 constant IC1x = 12678167458714289602959318889861294937001146728256270543982083502229223866662;
    uint256 constant IC1y = 2240307414988914777064087677401085328401423545878601107029315326478867524952;
    
    uint256 constant IC2x = 21513784345463726964802042090028242845385162590917257777971579627868201787984;
    uint256 constant IC2y = 20110319577955283823061037946544028098080538763639272373952803455004518469701;
    
    uint256 constant IC3x = 18277181548966296341643710736094565704776386158426045923886974418148170174569;
    uint256 constant IC3y = 4521522003933470622271328729409173477610633140483385263043273806305732470261;
    
    uint256 constant IC4x = 1566379818429353759486416972642273446245224062055655940015533505297654688032;
    uint256 constant IC4y = 18815526102899658230126388450091901283254408037352870078261861538820629787281;
    
    uint256 constant IC5x = 13697152442811669250023730249328774266152118377718947244988664718588795778083;
    uint256 constant IC5y = 8414885498774081607783859603467922395162486184068731961802306434692677584369;
    
    uint256 constant IC6x = 19283704166717461309081499998642058276871908379504684027378208974718999019796;
    uint256 constant IC6y = 6046022533308039487193942399301775757334361374583515979991830308167627252907;
    
    uint256 constant IC7x = 8231689618759586416414661120551903484541692477940674165329534111650530792147;
    uint256 constant IC7y = 12863724132694401359934333724953161248608195911025724108229836019136593590584;
    
    uint256 constant IC8x = 8619491561717889281867368181391937369235827391706934465918029630627793490867;
    uint256 constant IC8y = 9187354483151579637937613004555023171011054101969852726876409386512515370307;
    
    uint256 constant IC9x = 13066629532444262145441099003694403331100711340657926058837085468982062275150;
    uint256 constant IC9y = 16934467792192583370808203845503882995301782492389135956405751393454128917252;
    
    uint256 constant IC10x = 12631598567367073839912103117978470983850246924599754083685987482994718298320;
    uint256 constant IC10y = 19414977037875885228091591578090510773254557844231693644021662626197768079054;
    
    uint256 constant IC11x = 14587892132007765041981383169025746589171732783050888848482915406218658326623;
    uint256 constant IC11y = 13831750671543852671370047331434885534547372019095701703599517554751597927101;
    
    uint256 constant IC12x = 5000926500430849498890473594789842528106481224655951930696863636131316521273;
    uint256 constant IC12y = 11249026244248612614799061199533362182221206054986335863864599720897751005019;
    
    uint256 constant IC13x = 16399044266910992505468782226357526364495392828957778267456807284097925612181;
    uint256 constant IC13y = 10259764864532531458249191525020129312893849370310771167585136476015355119071;
    
    uint256 constant IC14x = 12340527940246973356876082926056499554627434245670727978479664306885118587813;
    uint256 constant IC14y = 15859193139246321009469105697773638131500777871215546818260421492675356340824;
    
    uint256 constant IC15x = 17765734544893002195534598785519265361986232988827554371414970315528911687885;
    uint256 constant IC15y = 10928618777679349072652431754516568708231353210345203959421335333175147123942;
    
    uint256 constant IC16x = 6147056069904993301826173318087269482043269266901345693418096415832019208077;
    uint256 constant IC16y = 3347521587364303925611801984389733376573682072546569926319428520438758235387;
    
    uint256 constant IC17x = 10258086466392741946898485452019278907298940273513310709044070920560824117531;
    uint256 constant IC17y = 10652826244051395950433059430295439033471283788241756193877114229673992510879;
    
    uint256 constant IC18x = 7966397291198388283846172657870083200468121214182312894497047190602930948392;
    uint256 constant IC18y = 8427684671336743660768191912833213818398443889842019228820016493210081448363;
    
    uint256 constant IC19x = 6497175430059342441975836121619282427027760496402139159110955174329365079118;
    uint256 constant IC19y = 14203959825339208608636821911227834819162659543567774121846327250790836684886;
    
    uint256 constant IC20x = 14135534086599991247050203273257277367626341889055972354646032710226515500721;
    uint256 constant IC20y = 19430302854921899746608861803581881990928743545384966135117728367372074000374;
    
 
    // Memory data
    uint16 constant pVk = 0;
    uint16 constant pPairing = 128;

    uint16 constant pLastMem = 896;

    function verifyProof(uint[2] calldata _pA, uint[2][2] calldata _pB, uint[2] calldata _pC, uint[20] calldata _pubSignals) public view returns (bool) {
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
            

            // Validate all evaluations
            let isValid := checkPairing(_pA, _pB, _pC, _pubSignals, pMem)

            mstore(0, isValid)
             return(0, 0x20)
         }
     }
 }
