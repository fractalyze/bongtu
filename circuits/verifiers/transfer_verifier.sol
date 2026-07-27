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

    
    uint256 constant IC0x = 19913502905424524650924950739251048600232195561050854513995572450618271527579;
    uint256 constant IC0y = 1731484251957160396375225591379842255193193973477513660660507642136673836180;
    
    uint256 constant IC1x = 3844278569649057580958753872910229988825702941917135010869157959573992843512;
    uint256 constant IC1y = 14876795297448783703980267335407015596860557927165866890301740135429101517664;
    
    uint256 constant IC2x = 16379882748572889408827242186650892522196959826775817295974482605050969121986;
    uint256 constant IC2y = 2615843721527751485127652326197217095431226795897600919221475589056771985604;
    
    uint256 constant IC3x = 9934710176595759447652707638017813812889003773383961205410580867453603074051;
    uint256 constant IC3y = 6409619179851804115210183371094159239977143960385976556568150020056947469417;
    
    uint256 constant IC4x = 16731338258832585016856036144741748845264038340485430057130966047789295030415;
    uint256 constant IC4y = 291375746516580553908326667270342367448950392316957263752807967427483833922;
    
    uint256 constant IC5x = 1286600657899442083738384448073540380070582984143533675265559212266180481471;
    uint256 constant IC5y = 14636297794396552495452779175144355510848258513491074809253275314500941304534;
    
    uint256 constant IC6x = 6422732742608377657122502080072102207938672296142930810931295028459294207;
    uint256 constant IC6y = 9064188334374351147828111924360246175247630772304429584324183208249966060132;
    
    uint256 constant IC7x = 9220361793018216084196488026359198074895839698562842001022719364561469387713;
    uint256 constant IC7y = 14819067998327442098520832713061059572798852427501394329896026077965518214502;
    
    uint256 constant IC8x = 11808008001445956407677456811782724653405764746007635028972148519052846076491;
    uint256 constant IC8y = 20398632082907228708991927259502722175291998019403258963973827590786831368400;
    
    uint256 constant IC9x = 548959462207181078259486771914549835864182713427722191582869098225198777744;
    uint256 constant IC9y = 18606531128852763658317303131984103268503704386179721518676205682098902587311;
    
    uint256 constant IC10x = 10554431756877476871425441624896059748099531096782789849461193606292361414523;
    uint256 constant IC10y = 4828940752082623131817644731106902734320603838762193739989518309111257361741;
    
    uint256 constant IC11x = 18155306618946621936096512983267640402469526930213045790181429335036589653521;
    uint256 constant IC11y = 11890880507087426828262920082312366492016774482220526055462865054094475767327;
    
    uint256 constant IC12x = 15545021614522085270599910944155749508562212365491358755201502956356084703759;
    uint256 constant IC12y = 9363519900012803402312924836964643252936930442936317115959467816438413856345;
    
    uint256 constant IC13x = 14833211681300853182744638451964154367489755470251886430481773979097097382728;
    uint256 constant IC13y = 18136244293941300671231995300220841818553932370745934075177637123088999091229;
    
    uint256 constant IC14x = 18848516946908380182147020835255542757647940221762373828419887416136601912494;
    uint256 constant IC14y = 8928924174127443355965067702275863877732168731499787764569228009546336080151;
    
    uint256 constant IC15x = 20217136100417155107782053132976237159078508793268236583825690508109559332476;
    uint256 constant IC15y = 14351788040383451345344000070064715648019973113171481213211331351308454719717;
    
    uint256 constant IC16x = 19695901036524423944011299742295594434294287927347597688866196480903088784554;
    uint256 constant IC16y = 57943905300483196181357644077523382029563610379894430968991997255515140186;
    
    uint256 constant IC17x = 16461221810860589226972581995706578685793717200613246213041592114501255857901;
    uint256 constant IC17y = 17321941908550403254431233999891285481790480563951313059307751517150233929612;
    
    uint256 constant IC18x = 4480154742758149161580941449402612381643804808032035557875968981622871360590;
    uint256 constant IC18y = 14242701162349268309038619952632087651759700038393281884437817228182853431040;
    
    uint256 constant IC19x = 6985750487810573517279827885074050478175101221719627030505109816518181521451;
    uint256 constant IC19y = 8611716942080677809924511312650126348642814123723062149388760222387814954672;
    
    uint256 constant IC20x = 4365643773256018856738443357011572131299313276197207268776903878656151131427;
    uint256 constant IC20y = 4221529137636986773802291251071260804151251930751907713893735133261578459518;
    
    uint256 constant IC21x = 4104438877370908782217329076723127457158330685660300503301694915585880238943;
    uint256 constant IC21y = 8785776827035995002127385215469077971973337257704697435684289905161643526896;
    
    uint256 constant IC22x = 1991998636063727434130872826781962614316035458743641092730740843612799120335;
    uint256 constant IC22y = 8032917696655641801969082222958171409444522183950817020537537686756051971009;
    
    uint256 constant IC23x = 21750781007780153507894214900801783105393228790972542864272349715090319115341;
    uint256 constant IC23y = 7275653902501804497963331774302803018636696188929263319838322687354173845001;
    
    uint256 constant IC24x = 292191374650556952624331070761266662358884371571366087379974620473562364682;
    uint256 constant IC24y = 11701154505575588013080291289004797799220959481192347690581386232865573117707;
    
    uint256 constant IC25x = 14622755286337028956529243003719093292915705133826459760713988632459932189684;
    uint256 constant IC25y = 19609406840916320020177678546334230428460864726882938120465646217195821465808;
    
    uint256 constant IC26x = 14540208707029330904753378818161514740636737186778342128274720390847793060458;
    uint256 constant IC26y = 4188247012166661485563953058681410827955310048285490309879170160823738692426;
    
    uint256 constant IC27x = 16600912015968261642166257437089153245671911490311793248809508819510578153419;
    uint256 constant IC27y = 7666031031665728574959970577413694431281025638013086327361174676157589987554;
    
    uint256 constant IC28x = 11286762688221799019367385873880343206016630621063276071990534785787429034506;
    uint256 constant IC28y = 2883210771039863171499055124426406673300779336149090821694936616134917604027;
    
    uint256 constant IC29x = 15625461502867518809671112638735317553883639697367940395293231345202464694459;
    uint256 constant IC29y = 13306190370363000175813139306384120253055283910735806245363435734670654409956;
    
    uint256 constant IC30x = 16721773422678880171693727433054519895408382041525965382410613056737788278855;
    uint256 constant IC30y = 11860559974613417740315172162538294834319665087532174303430099093595140364778;
    
    uint256 constant IC31x = 7764303663297903980310852759411161471359143028970714195919981112402510228837;
    uint256 constant IC31y = 5511542156835673642434839815258720773890560962556390047383485032628968257471;
    
    uint256 constant IC32x = 12530337413439981609512083316031463732974914987920202422668222632598710936974;
    uint256 constant IC32y = 7483651542539686469407005284121115827621887364271917418919089048325298503710;
    
    uint256 constant IC33x = 692649836990547478970089332755649537109819245798232333293169869001156228702;
    uint256 constant IC33y = 6715268891405513403019829067537917946589360900449549279792095132276659111027;
    
    uint256 constant IC34x = 15944130408293611893260680596830270880068142387884384508948707260567606203007;
    uint256 constant IC34y = 968448897392217236988792524164834452952854803385568002581725300117808060672;
    
    uint256 constant IC35x = 9952510249743296803245011776918667132280683636032217634283230158591633484279;
    uint256 constant IC35y = 7322610490418320665376148982575491998779322654840048730723260653900216377594;
    
    uint256 constant IC36x = 14829154342929395075891136741181762034016522998570310956309058174930450190253;
    uint256 constant IC36y = 18555589745492983085341044701431954450665350100039272688679270304475615339978;
    
    uint256 constant IC37x = 18438945654581753820899461313879838108072640935208124458002257697667255446035;
    uint256 constant IC37y = 6305933451692360101245092843760662543645716372088710296909853278905118824451;
    
 
    // Memory data
    uint16 constant pVk = 0;
    uint16 constant pPairing = 128;

    uint16 constant pLastMem = 896;

    function verifyProof(uint[2] calldata _pA, uint[2][2] calldata _pB, uint[2] calldata _pC, uint[37] calldata _pubSignals) public view returns (bool) {
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
                
                g1_mulAccC(_pVk, IC37x, IC37y, calldataload(add(pubSignals, 1152)))
                

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
            
            checkField(calldataload(add(_pubSignals, 1152)))
            

            // Validate all evaluations
            let isValid := checkPairing(_pA, _pB, _pC, _pubSignals, pMem)

            mstore(0, isValid)
             return(0, 0x20)
         }
     }
 }
